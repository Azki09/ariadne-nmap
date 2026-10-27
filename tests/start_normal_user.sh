#!/bin/sh
# Second app instance whose nmap has no capabilities (cp drops them): a normal user's first run.
set -e
mkdir -p /tmp/np /tmp/scans2
cp /usr/bin/nmap /tmp/np/nmap
getcap /tmp/np/nmap || true
cd /opt/ariadne
PATH=/tmp/np:$PATH ARIADNE_DATA=/tmp/scans2 ARIADNE_BIND=127.0.0.1 \
  nohup python3 app.py --port 8733 > /tmp/unpriv.log 2>&1 &
sleep 2
cat /tmp/unpriv.log
