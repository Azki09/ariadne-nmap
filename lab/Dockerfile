# A target with several common services, for testing Ariadne.
# TCP: 21 ftp, 22 ssh, 53 dns, 8888 http proxy.  UDP: 53 dns, 161 snmp.
FROM alpine:3.20

RUN apk add --no-cache openssh-server dnsmasq vsftpd tinyproxy net-snmp \
 && ssh-keygen -A \
 && echo "root:lab-only-password" | chpasswd \
 && mkdir -p /var/empty/vsftpd

COPY vsftpd.conf /etc/vsftpd/vsftpd.conf
COPY start.sh /start.sh
RUN sed -i 's/\r$//' /start.sh /etc/vsftpd/vsftpd.conf && chmod +x /start.sh

CMD ["/start.sh"]
