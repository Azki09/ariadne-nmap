#!/bin/sh
# Print raw --packet-trace lines for the scan types the Packets tab reads.
# Run inside a distro container on the lab network.
for a in "-sS -p 22,80,81" "-sT -p 22,23" "-sU -p 53,54" "-sn -PE --send-ip" "-sS -p 22 --send-ip -Pn"; do
  nmap --privileged $a --packet-trace 172.30.0.40 -oX /dev/null 2>/dev/null | grep -E '^(SENT|RCVD|CONN) '
done
nmap --privileged -6 -sS -p 80 --packet-trace fd00:30::20 -oX /dev/null 2>/dev/null | grep -E '^(SENT|RCVD|CONN) '
nmap --privileged -6 -sU -p 53,54 --packet-trace fd00:30::40 -oX /dev/null 2>/dev/null | grep -E '^(SENT|RCVD|CONN) '
