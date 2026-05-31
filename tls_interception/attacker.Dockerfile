FROM python:3.13-bookworm
RUN apt update && apt install iproute2 vim nano iputils-ping net-tools netcat-traditional libpcap-dev -y
RUN pip install scapy
RUN pip install pyopenssl
RUN apt install iptables -y

COPY ./certificate /certificate