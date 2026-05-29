FROM python:3.13-bookworm
RUN apt update && apt install iproute2 vim nano iputils-ping net-tools netcat-traditional libpcap-dev -y

COPY send_commands.py /send_commands.py
