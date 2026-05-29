import socket
import time
import sys
import random

messages = [
    "You're the SSL to my HTTP.",
    "You make my heart skip a bit.",
    "My firewall would never block your love.",
    "Our connection is more stable than my Wi-Fi.",
    "Don't worry, my affection is DoS-resistant!",
    "I tunneled my feelings through SSH.",
    "You must be a router, because you direct my heart.",
    "I scanned your ports and found... love.",
    "Our bond is stronger than a TCP handshake!",
    "Even NAT can't hide my feelings.",
    "I've got 99 problems, but an open port ain't one.",
    "You're so secure, even Wireshark can't decode you.",
    "Can I get your MAC address? For science, of course.",
    "Your packets would never drop with me. :3",
    "My love is persistent like a SYN flood.",
    "Are you a DNS server? Because I can't resolve my feelings.",
    "I must be a packet, because I'm lost without you.",
    "You had me at 'Hello World'.",
    "I wish I was your subnet mask, so I could be with you all the time.",
    "Are you a VPN? Because you make me feel secure.",
    "I don't need a proxy to see how great you are.",
    "I don't need a network analyzer to see how much I like you.",
]

def get_random_message():
    return random.choice(messages)

def chat_loop(conn, role, send_first):
    while True:
        if send_first:
            time.sleep(1)
            msg = get_random_message()
            conn.sendall(msg.encode() + b'\n')
            print(f"[{role}] sent: {msg}", flush=True)

        data = conn.recv(1024)
        if not data:
            print(f"[{role}] Connection closed by peer.", flush=True)
            break
        print(f"[{role}] received: {data.decode().strip()}", flush=True)

        time.sleep(1)
        msg = get_random_message()
        conn.sendall(msg.encode() + b'\n')
        print(f"[{role}] sent: {msg}", flush=True)
        
        send_first = False

def listener_mode(port, host='0.0.0.0'):
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.listen()
                print(f"[Listener] Listening on {host}:{port}...", flush=True)
                conn, addr = s.accept()
                print(f"[Listener] Connected to {addr}", flush=True)
                chat_loop(conn, "Listener", send_first=False)
        except (ConnectionResetError, ConnectionAbortedError) as e:
            print(f"[Listener] got exception: {e}", flush=True)
        time.sleep(5)

def client_mode(server_host, server_port):
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_host, server_port))
                print(f"[Client] Connected to {server_host}:{server_port}", flush=True)
                chat_loop(s, "Client", send_first=True)
        except (ConnectionRefusedError, socket.timeout) as e:
            print(f"[Client] Could not connect to server: {e}", flush=True)
        except (ConnectionResetError, ConnectionAbortedError) as e:
            print(f"[Client] got exception: {e}", flush=True)
        time.sleep(5)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage:\n  Listener: python {sys.argv[0]} listen <port>\n  Client: python {sys.argv[0]} connect <host> <port>", flush=True)
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "listen":
        if len(sys.argv) < 3:
            print(f"Usage: python {sys.argv[0]} listen <port>", flush=True)
            sys.exit(1)
        port = int(sys.argv[2])
        listener_mode(port)
    elif mode == "connect":
        if len(sys.argv) < 4:
            print(f"Usage: python {sys.argv[0]} connect <host> <port>", flush=True)
            sys.exit(1)
        host = sys.argv[2]
        port = int(sys.argv[3])
        client_mode(host, port)
    else:
        print("Unknown mode. Use 'listen' or 'connect'.", flush=True)
        sys.exit(1)
