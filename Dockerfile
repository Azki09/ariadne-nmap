# Ariadne test image: Ubuntu + the distribution's nmap + the app.
# Used to try the app on Linux from any machine. See docker-compose.yml.
FROM ubuntu:24.04

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap python3 libcap2-bin iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*

# Run as a normal user, like a real desktop install. nmap gets the same
# capabilities the app tells users to grant with setcap, so -sS / -O work.
# The container must be started with NET_RAW and NET_ADMIN (see compose file),
# otherwise the kernel refuses to run a binary with these file capabilities.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" \
 && useradd --create-home --shell /bin/bash navigator \
 && install -d -o navigator -g navigator /home/navigator/scans

WORKDIR /opt/ariadne
COPY prototype/app.py prototype/index.html prototype/start.sh ./

USER navigator
ENV ARIADNE_BIND=0.0.0.0 \
    ARIADNE_DATA=/home/navigator/scans \
    PYTHONUNBUFFERED=1
EXPOSE 8732
CMD ["python3", "app.py"]
