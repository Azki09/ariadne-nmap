# Ariadne on another distribution, with that distribution's own nmap
# and Python. Build from the project root:
#   docker build -f tests/distros/Dockerfile --build-arg BASE=debian:12 -t nn-debian12 .
ARG BASE=debian:12
FROM ${BASE}

RUN set -e; \
    if command -v apt-get >/dev/null; then \
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nmap python3 libcap2-bin iproute2 && rm -rf /var/lib/apt/lists/*; \
    elif command -v dnf >/dev/null; then \
      dnf install -y nmap python3 libcap shadow-utils iproute && dnf clean all; \
    elif command -v pacman >/dev/null; then \
      pacman -Syu --noconfirm nmap python libcap iproute2 && pacman -Scc --noconfirm; \
    elif command -v zypper >/dev/null; then \
      zypper --non-interactive install nmap python3 libcap-progs shadow iproute2 && zypper clean -a; \
    elif command -v apk >/dev/null; then \
      apk add --no-cache nmap nmap-scripts nmap-nselibs python3 libcap-utils iproute2 shadow; \
    else echo "unknown package manager" >&2; exit 1; fi; \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"; \
    useradd --create-home --shell /bin/sh navigator; \
    install -d -o navigator -g navigator /home/navigator/scans; \
    printf 'nmap: '; nmap --version | head -1; python3 --version

WORKDIR /opt/ariadne
COPY prototype/app.py prototype/index.html ./

USER navigator
ENV ARIADNE_BIND=0.0.0.0 \
    ARIADNE_DATA=/home/navigator/scans \
    PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "app.py"]
