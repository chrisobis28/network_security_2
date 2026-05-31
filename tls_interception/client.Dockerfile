FROM debian:bookworm
RUN apt update && apt install iproute2 vim nano iputils-ping net-tools netcat-traditional libpcap-dev curl -y

RUN apt install ca-certificates -y
COPY ./certificate/rootCA.crt /usr/local/share/ca-certificates/rootCA.crt
RUN update-ca-certificates
