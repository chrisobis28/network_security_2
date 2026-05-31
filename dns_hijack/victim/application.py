#!/usr/bin/env python3

import datetime
import socket
import time

domain = f"update-server.updateserver.corp"
while True:
    print(f"{datetime.datetime.now().isoformat()} Querying {domain}")
    try:
        ipaddr = {a[4][0] for a in socket.getaddrinfo(domain, 0, socket.AF_INET)}
        print(f"{datetime.datetime.now().isoformat()} Got answer {ipaddr} for {domain}")
        if "254.123.45.67" not in ipaddr:
            print(f"{datetime.datetime.now().isoformat()} Oh no, my DNS has been hijacked!")
    except Exception as e:
        print(f"{datetime.datetime.now().isoformat()} Got error {e} for {domain}")

    time.sleep(10)
