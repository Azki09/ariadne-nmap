#!/bin/sh
# Start every lab service in the background, then wait.
/usr/sbin/sshd
dnsmasq --no-resolv --address=/lab.test/172.30.0.40 --host-record=web.lab.test,172.30.0.20
vsftpd /etc/vsftpd/vsftpd.conf &
sed -i 's/^Port .*/Port 8888/; s/^#\?Allow 127.0.0.1/Allow 172.30.0.0\/24/' /etc/tinyproxy/tinyproxy.conf
tinyproxy
snmpd -Lo -C -c /dev/null --rocommunity=public udp:161
exec tail -f /dev/null
