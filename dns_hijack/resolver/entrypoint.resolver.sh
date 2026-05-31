#!/bin/bash

# how this works:
# user requests a query at 0.0.0.0:53

# listening on port 5353 is the dns server that forwards to the authoritive nameserver
dnsmasq --listen-address=127.0.0.1 --port 5353 --no-resolv --server '192.168.124.11' --log-facility=- --log-queries
# listening on port 53 is a delaying proxy to ensure we can actually intercept requests
/opt/proxy.py 0.0.0.0 53 127.0.0.1 5353 --sleep=0.1
