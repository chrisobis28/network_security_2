FROM python:3.13-bookworm
RUN apt update && apt install iproute2 vim nano iputils-ping net-tools netcat-traditional libpcap-dev -y

RUN apt install dnsmasq -y

COPY entrypoint.resolver.sh /entrypoint.sh
COPY udp_proxy.py /opt/proxy.py
RUN chmod +x /entrypoint.sh /opt/proxy.py
