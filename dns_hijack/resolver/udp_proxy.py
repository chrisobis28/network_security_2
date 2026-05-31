#!/usr/bin/env python3

import argparse
import datetime
import socket
import threading
import time


parser = argparse.ArgumentParser()
parser.add_argument("listen_address")
parser.add_argument("listen_port", type=int)
parser.add_argument("forward_address")
parser.add_argument("forward_port", type=int)
parser.add_argument("--sleep", type=float, default=0.5)
args = parser.parse_args()


def _addr(addr):
    return ':'.join(map(str, addr))


class ListenThread(threading.Thread):
    def __init__(self, socket, addr):
        super().__init__()
    
        self.socket = socket
        self.socket.settimeout(30 + args.sleep)
        self.addr = addr

    def run(self):
        while True:
            try:
                data, r_addr = self.socket.recvfrom(65536)
            except socket.timeout:
                break
            print(f"{datetime.datetime.now().isoformat()} {_addr(self.addr)} Received {len(data)} bytes from server")

            # sleep a little while to make it easier to quantum insert stuff
            time.sleep(args.sleep)

            server_socket.sendto(data, self.addr)

        with socket_lock:
            print(f"{datetime.datetime.now().isoformat()} {_addr(self.addr)} Terminated connection")
            self.socket.close()
            sockets.pop(self.addr)


# Listen on port 53 for all interfaces
print(f"{datetime.datetime.now().isoformat()} Starting UDP forwarder on {args.listen_address}:{args.listen_port}")
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((args.listen_address, args.listen_port))

sockets = {}
socket_lock = threading.Lock()
while True:
    data, addr = server_socket.recvfrom(65536)
    print(f"{datetime.datetime.now().isoformat()} {_addr(addr)} Received {len(data)} bytes from client")

    # sleep a little while to make it easier to quantum insert stuff
    time.sleep(args.sleep)

    with socket_lock:
        if addr not in sockets:
            print(f"{datetime.datetime.now().isoformat()} {_addr(addr)} Received connection")
            sockets[addr] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            t = ListenThread(socket=sockets[addr], addr=addr)
            t.start()

        sockets[addr].sendto(data, (args.forward_address, args.forward_port))
