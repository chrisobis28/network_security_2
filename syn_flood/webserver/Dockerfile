FROM httpd:2.4
RUN apt update && apt install net-tools iproute2 tcpdump -y

RUN apt install -y iptables-persistent

COPY ./public-html/ /usr/local/apache2/htdocs/

# Disable Keep-Alive
RUN echo "KeepAlive Off" >> /usr/local/apache2/conf/httpd.conf

# Firewall configuration
COPY rules.v4 /etc/iptables/rules.v4
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
