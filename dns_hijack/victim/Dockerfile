FROM python:3.13-bookworm
RUN apt update && apt install iproute2 vim nano iputils-ping net-tools netcat-traditional libpcap-dev -y

RUN apt install dnsutils -y

COPY application.py /opt/application.py
RUN chmod +x /opt/application.py
