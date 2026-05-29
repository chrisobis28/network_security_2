FROM python:3.13-bookworm
RUN apt update && apt install iproute2 vim nano iputils-ping net-tools netcat-traditional libpcap-dev -y

RUN apt install -y iptables-persistent

RUN apt install -y cowsay fortune-mod

RUN useradd -m -s /bin/bash user

COPY rules.v4 /etc/iptables/rules.v4
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
