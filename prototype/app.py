#!/usr/bin/env python3
"""Ariadne - local backend.

Serves the page (index.html) and runs the real `nmap` already installed on this
machine, streaming its progress and results back to the page as it scans.

Design goals:
  * Standard library only. No pip install, no build step. Just `python3 app.py`.
  * Listens on 127.0.0.1 only. Never exposed to the network. (The Docker test
    setup uses --bind 0.0.0.0 inside the container and publishes the port on
    the host's 127.0.0.1 only.)
  * nmap is launched with an argument array, never through a shell, so there is
    no command-injection surface.
  * Every flag the page sends is checked against an allow-list taken from the
    option catalog. Unknown or risky flags are refused with a clear message.
  * File-reading / file-writing flags are disabled in this version; the backend
    reads nmap's XML through a pipe of its own (stdout on Windows) and keeps
    its own copy of every scan in the history folder (see --data-dir).
  * Other web pages open in the same browser must not be able to drive it:
    every /api request needs the per-run token that only our own page gets,
    and requests with a foreign Host or Origin header are refused.

Run:
    python3 app.py                # then open http://127.0.0.1:8732
    python3 app.py --open         # same, and open the browser for you
    python3 app.py --selftest     # check the arg checker, parser and guards without nmap
    python3 app.py --port 9000    # use another port
    python3 app.py --version      # print the app version

Scan only machines you own or are authorized to test.
"""

import argparse
import errno
import hmac
import html
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import webbrowser
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# The only place the version is written; the page reads it from /api/env.
APP_VERSION = "1.0.0"

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index.html")
DEFAULT_PORT = 8732

# Handed to our own page inside index.html and required on every /api request.
# A page from another site cannot read index.html (no CORS), so it never learns it.
TOKEN = secrets.token_urlsafe(32)
TOKEN_HEADER = "X-Ariadne-Token"

# --------------------------------------------------------------------------
# Flag allow-list (mirrors the catalog in index.html)
# --------------------------------------------------------------------------

# Flags that stand alone (no value follows).
BARE_FLAGS = {
    # techniques
    "-sS", "-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX",
    "-sU", "-sY", "-sZ", "-sO",
    # discovery
    "-sn", "-sL", "-Pn", "-PE", "-PP", "-PM",
    "-n", "-R", "--system-dns", "--traceroute",
    # ports
    "-F", "-r", "-p-",
    # detection / scripts / os
    "-sV", "--version-light", "--version-all", "--version-trace",
    "-sC", "--script-trace",
    "-O", "--osscan-limit", "--osscan-guess",
    # evasion
    "-f", "--badsum",
    # output (screen only)
    "--reason", "--open", "--packet-trace", "-v", "-vv", "-d", "-dd",
    # misc
    "-6", "-A", "--send-eth", "--send-ip",
    # privilege hints (harmless; backend decides for real)
    "--privileged", "--unprivileged", "--noninteractive",
}

# Flags that take the next token as their value.
VALUE_FLAGS = {
    "-p", "--top-ports", "--exclude-ports", "--port-ratio",
    "--scanflags", "-sI", "-b",
    "--dns-servers",
    "--version-intensity",
    "--script", "--script-args",
    "-D", "-S", "-e", "-g", "--source-port", "--proxies",
    "--data", "--data-string", "--data-length", "--ip-options",
    "--ttl", "--spoof-mac", "--mtu",
    "--min-rate", "--max-rate", "--min-parallelism", "--max-parallelism",
    "--min-hostgroup", "--max-hostgroup", "--max-retries",
    "--host-timeout", "--scan-delay", "--max-scan-delay",
    "--initial-rtt-timeout", "--min-rtt-timeout", "--max-rtt-timeout",
    "-iR", "--exclude",
}

# Values that may contain spaces (free text). nmap gets them as one argument.
SPACED_VALUES = {"--data-string", "--script-args"}

# Attached forms: prefix -> regex the whole token must match.
ATTACHED = [
    (re.compile(r"^-T[0-5]$"), None),
    (re.compile(r"^-P[SAUYO][0-9,\-]*$"), None),   # -PS80,443 etc.
    (re.compile(r"^--script=[A-Za-z0-9_,.*/+\-]+$"), None),
    (re.compile(r"^-p[0-9TUS].*$"), None),          # -p22 attached form
]

# Flags refused in this version, with an explanation for the user.
DISABLED_FLAGS = {
    "-oN": "Saving to files is managed by the app in this version.",
    "-oX": "The app already collects XML; a second -oX is not needed.",
    "-oG": "Saving to files is managed by the app in this version.",
    "-oS": "Saving to files is managed by the app in this version.",
    "-oA": "Saving to files is managed by the app in this version.",
    "--append-output": "File output is disabled in this version.",
    "--stylesheet": "File output is disabled in this version.",
    "--webxml": "File output is disabled in this version.",
    "--no-stylesheet": "File output is disabled in this version.",
    "--resume": "Resuming a saved scan is not supported yet.",
    "-iL": "Reading targets from a file is not supported yet.",
    "--excludefile": "Reading a file is not supported yet.",
    "--script-args-file": "Reading a file is not supported yet.",
    "--datadir": "Custom data directories are not supported yet.",
}

# Every token must match this. There is no shell, so this is belt-and-suspenders
# against surprising input; it also rejects whitespace and shell metacharacters.
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._:/@,=+%\[\]\-]+$")
SPACED_TOKEN = re.compile(r"^[A-Za-z0-9._:/@,=+%\[\]\- ]+$")
TARGET_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]*$")


class ValidationError(Exception):
    pass


def validate(args):
    """Turn the page's arg list into a safe argv for nmap, or raise.

    Returns (argv, targets). Raises ValidationError with a friendly message.
    """
    # The page sends "flag value" joined in one element, and several targets in
    # one element; re-split on spaces. Safe because we reject metacharacters and
    # never use a shell. A value flag keeps the rest of its element as the value
    # (quotes stripped), so free text like --data-string "authorized test" works.
    tokens = []
    for a in args:
        if not isinstance(a, str):
            raise ValidationError("Every argument must be text.")
        parts = a.split(None, 1)
        if len(parts) == 2 and parts[0] in VALUE_FLAGS:
            val = parts[1].strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1].strip()
            if parts[0] not in SPACED_VALUES:
                val = re.sub(r"\s*,\s*", ",", val)  # "22, 80" -> "22,80"
            tokens.extend([parts[0], val])
        else:
            tokens.extend(a.split())

    argv, targets = [], []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if not SAFE_TOKEN.match(t):
            raise ValidationError("Argument contains characters that are not allowed: %r" % t)
        if t in DISABLED_FLAGS:
            raise ValidationError("%s is not available in this version. %s" % (t, DISABLED_FLAGS[t]))
        if t in BARE_FLAGS:
            argv.append(t)
            i += 1
            continue
        if t in VALUE_FLAGS:
            if i + 1 >= len(tokens):
                raise ValidationError("%s expects a value after it." % t)
            val = tokens[i + 1]
            ok = SPACED_TOKEN if t in SPACED_VALUES else SAFE_TOKEN
            if not ok.match(val):
                raise ValidationError("The value for %s is not allowed: %r" % (t, val))
            argv.extend([t, val])
            i += 2
            continue
        if any(rx.match(t) for rx, _ in ATTACHED):
            argv.append(t)
            i += 1
            continue
        if t.startswith("-"):
            raise ValidationError("Unknown or unsupported flag: %s" % t)
        # Otherwise a target.
        if not TARGET_TOKEN.match(t):
            raise ValidationError("That does not look like a valid target: %r" % t)
        targets.append(t)
        argv.append(t)
        i += 1

    if not targets and "-iR" not in argv:
        raise ValidationError("No target to scan. Add a host, IP or range.")
    return argv, targets


# --------------------------------------------------------------------------
# Environment detection
# --------------------------------------------------------------------------

def nmap_path():
    # Prefer the copy bundled next to app.py (prototype/nmap/), then PATH.
    bundled = shutil.which("nmap", path=os.path.join(HERE, "nmap"))
    return bundled or shutil.which("nmap")


def nmap_version(path):
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
        m = re.search(r"Nmap version (\S+)", out.stdout)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


_WIN_RAW = {}  # nmap path -> result of the raw-packet probe (cached; it takes ~1s)


def windows_raw_probe(path):
    """On Windows, raw access depends on Npcap and its settings, not on one flag.
    Ask nmap itself: a 1-port SYN scan of loopback either runs as "syn" or fails."""
    if path not in _WIN_RAW:
        ok = False
        try:
            out = subprocess.run([path, "-sS", "-Pn", "-n", "-p", "1", "--max-retries", "0",
                                  "127.0.0.1", "-oX", "-", "--noninteractive"],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20)
            ok = out.returncode == 0 and 'type="syn"' in out.stdout
        except Exception:
            pass
        _WIN_RAW[path] = ok
    return _WIN_RAW[path]


def privilege_info(path):
    """Return (privileged, short reason shown in the UI)."""
    if sys.platform == "win32":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return True, "Administrator"
        except Exception:
            pass
        if path and windows_raw_probe(path):
            return True, "Npcap raw access"
        return False, "Normal user (no Npcap raw access)"
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True, "root"
    except Exception:
        pass
    getcap = shutil.which("getcap")
    if getcap and path:
        try:
            out = subprocess.run([getcap, path], capture_output=True, text=True, timeout=10)
            if "cap_net_raw" in out.stdout:
                return True, "cap_net_raw"
        except Exception:
            pass
    return False, "Normal user"


def is_privileged(path):
    return privilege_info(path)[0]


def interfaces(path):
    """Parse `nmap --iflist` into a small list of interfaces."""
    ifaces = []
    if not path:
        return ifaces
    try:
        out = subprocess.run([path, "--iflist"], capture_output=True, text=True, timeout=10)
    except Exception:
        return ifaces
    in_if = in_routes = False
    default_metric = {}  # dev -> lowest metric of its IPv4 default route
    for line in out.stdout.splitlines():
        if "INTERFACES" in line:
            in_if = True
            continue
        if "ROUTES" in line:
            in_if, in_routes = False, True
            continue
        if in_routes:
            parts = line.split()
            # DST/MASK DEV METRIC [GATEWAY]
            if len(parts) >= 3 and parts[0] == "0.0.0.0/0" and parts[2].isdigit():
                m = int(parts[2])
                default_metric[parts[1]] = min(m, default_metric.get(parts[1], m))
            continue
        if not in_if:
            continue
        parts = line.split()
        # DEV (SHORT) IP/MASK TYPE UP MTU [MAC]; skip that header row itself.
        if len(parts) >= 3 and "/" in parts[2] and parts[0] != "DEV":
            ifaces.append({"dev": parts[0].strip("()"), "addr": parts[2],
                           "up": "up" in parts, "mac": parts[-1] if ":" in parts[-1] else ""})
    for i in ifaces:
        i["default_metric"] = default_metric.get(i["dev"])
    return ifaces


def os_release():
    # Which Linux family this is, so the first-run guide can show the right install command.
    info = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                if k in ("ID", "ID_LIKE", "PRETTY_NAME"):
                    info[k.lower()] = v.strip().strip('"')
    except OSError:
        pass
    return info


def env_payload():
    path = nmap_path()
    priv, priv_note = privilege_info(path) if path else (False, "")
    return {
        "app_version": APP_VERSION,
        "found": bool(path),
        "path": path or "",
        # setcap needs the real file, not a symlink to it.
        "real_path": os.path.realpath(path) if path else "",
        "os": os_release(),
        "version": nmap_version(path) if path else "",
        "privileged": priv,
        "privilege_note": priv_note,
        "interfaces": interfaces(path),
        "platform": sys.platform,
        "data_dir": HISTORY.path,
        "disabled": DISABLED_FLAGS,
    }


# --------------------------------------------------------------------------
# Plain-language notes for open ports (shown in the UI and in reports)
# --------------------------------------------------------------------------

SERVICE_NOTES = {
    "ssh": "Remote login and file transfer (SSH). Fine to expose if it uses keys or strong passwords and is kept up to date.",
    "telnet": "Old remote login that sends everything, passwords included, in plain text. Replace it with SSH.",
    "ftp": "File transfer (FTP). Logins and files travel unencrypted; prefer SFTP. Check that anonymous login is off.",
    "smtp": "Mail server that accepts email (SMTP). Normal on a mail server; on other machines it is often an unneeded service.",
    "submission": "Port where mail programs hand outgoing email to the server. Normal on a mail server.",
    "domain": "DNS server: turns names into addresses. Routers run one for the home network; on the Internet it should not answer everyone.",
    "http": "A web server without encryption. Anything sent to it, passwords included, travels in plain text.",
    "https": "A web server with encryption (HTTPS).",
    "http-proxy": "Usually a web proxy or a second web server (often port 8080). Check whether other machines really need to reach it.",
    "http-alt": "An alternative web server port, common for apps and development servers.",
    "pop3": "Mailbox access (POP3). Without TLS, passwords travel in plain text; prefer POP3S on port 995.",
    "imap": "Mailbox access (IMAP). Without TLS, passwords travel in plain text; prefer IMAPS on port 993.",
    "pop3s": "Encrypted mailbox access (POP3 over TLS).",
    "imaps": "Encrypted mailbox access (IMAP over TLS).",
    "netbios-ssn": "Windows file and printer sharing (NetBIOS). Should only be reachable inside a trusted local network.",
    "microsoft-ds": "Windows file sharing (SMB). A common attack target; never expose it to the Internet.",
    "msrpc": "Windows remote procedure calls. Normal inside a Windows network; should not be reachable from the Internet.",
    "ms-wbt-server": "Windows Remote Desktop (RDP). A frequent target of password guessing; keep it behind a VPN if you can.",
    "vnc": "Remote desktop (VNC). Often weakly protected; use a strong password and keep it off the Internet.",
    "x11": "A Linux graphical display reachable over the network. Rarely intended: whoever connects may see or control the screen.",
    "mysql": "MySQL or MariaDB database. Usually only an app on the same machine needs it; check whether it must accept network connections.",
    "postgresql": "PostgreSQL database. Usually only an app on the same machine needs it; check whether it must accept network connections.",
    "ms-sql-s": "Microsoft SQL Server database. Should only be reachable by the apps that use it.",
    "redis": "Redis database. Default setups may accept commands without a password; never expose it to the Internet.",
    "mongodb": "MongoDB database. Many data leaks came from MongoDB left open without a password.",
    "docker": "Docker API. Without TLS, anyone who reaches it controls the containers and the machine. Never open it to the network.",
    "rpcbind": "Directory of RPC services, used by NFS on Linux. Not needed on most desktops; should not face the Internet.",
    "nfs": "Network file sharing (NFS). Check which folders are shared and with which machines.",
    "ipp": "Printing service (IPP/CUPS). On a computer it normally listens only to itself; on a printer it receives print jobs.",
    "jetdirect": "Raw printing port. Anything sent here gets printed.",
    "snmp": "Device monitoring (SNMP). Old setups use 'public' as the password; change it or turn SNMP off.",
    "upnp": "UPnP lets devices open router ports by themselves. Convenient but risky; consider turning it off on the router.",
    "ntp": "Time synchronization (NTP).",
    "zeroconf": "Local network discovery (mDNS, Bonjour, Avahi). Normal on home networks.",
    "mdns": "Local network discovery (mDNS, Bonjour, Avahi). Normal on home networks.",
    "dhcpc": "DHCP client: how this device gets its address from the router.",
    "dhcps": "DHCP server: hands out addresses on the local network. Normal on a router.",
    "ldap": "Directory service (LDAP), typical of company networks and Windows domain controllers.",
    "kerberos-sec": "Kerberos login service, typical of Windows domain controllers.",
    "sip": "Internet telephony (VoIP).",
    "rtsp": "Video streaming (RTSP), common on IP cameras. Make sure the camera has its own password.",
    "nping-echo": "The Nping echo service the Nmap project runs on scanme for testing.",
    "tcpwrapped": "The port accepted the connection and closed it at once, usually because of access rules. Nmap cannot tell what runs there.",
}
SERVICE_ALIASES = {"ssl/http": "https", "https-alt": "https", "ssl/https": "https", "http-mgmt": "http"}


def port_note(port):
    """A short, plain-language explanation for an open port, or "" if we have none."""
    if not port.get("state", "").startswith("open"):
        return ""
    svc = port.get("service") or {}
    name = svc.get("name", "") or "unknown"
    key = "ssl/" + name if svc.get("tunnel") == "ssl" else name
    key = SERVICE_ALIASES.get(key, key)
    if key.startswith("ssl/"):
        key = key[4:]
    note = SERVICE_NOTES.get(key, "")
    if name == "unknown":
        note = "Nmap could not tell which program uses this port. Add -sV so Nmap asks the service directly."
    if note and svc.get("method") == "table" and port.get("state") == "open":
        note += " (Guessed from the port number only; add -sV to confirm.)"
    return note


# --------------------------------------------------------------------------
# XML -> JSON for a single <host>
# --------------------------------------------------------------------------

def parse_host(h):
    out = {"addresses": [], "hostnames": [], "ports": [], "extraports": [],
           "status": "", "reason": "", "os": "", "distance": None, "mac": "", "vendor": ""}
    st = h.find("status")
    if st is not None:
        out["status"] = st.get("state", "")
        out["reason"] = st.get("reason", "")
    for a in h.findall("address"):
        kind = a.get("addrtype", "")
        out["addresses"].append({"addr": a.get("addr", ""), "type": kind, "vendor": a.get("vendor", "")})
        if kind == "mac":
            out["mac"] = a.get("addr", "")
            out["vendor"] = a.get("vendor", "")
    hn = h.find("hostnames")
    if hn is not None:
        out["hostnames"] = [n.get("name", "") for n in hn.findall("hostname") if n.get("name")]
    ports = h.find("ports")
    if ports is not None:
        for ep in ports.findall("extraports"):
            out["extraports"].append({"state": ep.get("state", ""), "count": ep.get("count", "")})
        for p in ports.findall("port"):
            svc = p.find("service")
            state = p.find("state")
            scripts = [{"id": s.get("id", ""), "output": s.get("output", "")}
                       for s in p.findall("script")]
            service = {}
            if svc is not None:
                service = {k: svc.get(k, "") for k in ("name", "product", "version", "extrainfo", "tunnel", "method")}
            entry = {
                "protocol": p.get("protocol", ""),
                "portid": int(p.get("portid", "0") or 0),
                "state": state.get("state", "") if state is not None else "",
                "reason": state.get("reason", "") if state is not None else "",
                "service": service,
                "scripts": scripts,
            }
            entry["note"] = port_note(entry)
            out["ports"].append(entry)
    os_el = h.find("os")
    if os_el is not None:
        m = os_el.find("osmatch")
        if m is not None:
            out["os"] = "%s (%s%%)" % (m.get("name", ""), m.get("accuracy", ""))
    d = h.find("distance")
    if d is not None:
        out["distance"] = int(d.get("value", "0") or 0)
    t = h.find("times")
    if t is not None:
        out["srtt"] = t.get("srtt", "")
    return out


# --------------------------------------------------------------------------
# Scan history (one XML + one JSON file per scan)
# --------------------------------------------------------------------------

SCAN_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")


def default_data_dir():
    if os.environ.get("ARIADNE_DATA"):
        return os.environ["ARIADNE_DATA"]
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "ariadne", "scans")


class History:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    @staticmethod
    def new_id():
        return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)

    def _file(self, sid, ext):
        # The id is the only part of the path that comes from the request.
        if not isinstance(sid, str) or not SCAN_ID.match(sid):
            return None
        return os.path.join(self.path, sid + ext)

    def _write(self, dest, data):
        tmp = dest + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, dest)

    def save(self, record, xml_bytes):
        with self.lock:
            os.makedirs(self.path, exist_ok=True)
            # XML first: a record that shows up in the list always has its XML.
            self._write(self._file(record["id"], ".xml"), bytes(xml_bytes))
            self._write(self._file(record["id"], ".json"), json.dumps(record, indent=1).encode("utf-8"))

    def get(self, sid):
        f = self._file(sid, ".json")
        if not f or not os.path.isfile(f):
            return None
        with open(f, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))

    def xml(self, sid):
        f = self._file(sid, ".xml")
        if not f or not os.path.isfile(f):
            return None
        with open(f, "rb") as fh:
            return fh.read()

    def list(self):
        """Newest first, without the per-host details."""
        if not os.path.isdir(self.path):
            return []
        out = []
        for name in os.listdir(self.path):
            if not name.endswith(".json") or not SCAN_ID.match(name[:-5]):
                continue
            try:
                rec = self.get(name[:-5])
            except (OSError, ValueError):
                continue
            if rec:
                rec.pop("hosts", None)
                out.append(rec)
        out.sort(key=lambda r: r.get("id", ""), reverse=True)
        return out

    def delete(self, sid):
        found = False
        with self.lock:
            for ext in (".json", ".xml"):
                f = self._file(sid, ext)
                if f and os.path.isfile(f):
                    os.remove(f)
                    found = True
        return found


HISTORY = History(default_data_dir())


def host_key(h):
    """IPv4 first, so the same machine lines up across scans."""
    addrs = h.get("addresses") or []
    for a in addrs:
        if a.get("type") == "ipv4":
            return a.get("addr", "")
    return addrs[0].get("addr", "") if addrs else ""


def _svc_label(p):
    s = p.get("service") or {}
    name = ("ssl/" if s.get("tunnel") == "ssl" else "") + (s.get("name") or "unknown")
    ver = " ".join(x for x in (s.get("product"), s.get("version")) if x)
    return name + (" " + ver if ver else "")


def diff_scans(old, new):
    """Compare two saved scans host by host and port by port.

    Ports that nmap did not list on one side were closed, filtered or not
    scanned there (nmap folds those into "Not shown"), so they are reported as
    appearing / disappearing rather than guessed.
    """
    a = {host_key(h): h for h in old.get("hosts", []) if h.get("status") == "up"}
    b = {host_key(h): h for h in new.get("hosts", []) if h.get("status") == "up"}
    hosts, counts = [], {"new_hosts": 0, "gone_hosts": 0, "opened": 0, "closed": 0, "changed": 0}
    for key in sorted(set(a) | set(b), key=_addr_sort):
        ha, hb = a.get(key), b.get(key)
        entry = {"addr": key, "name": ((hb or ha).get("hostnames") or [""])[0], "change": "same", "ports": []}
        if ha is None:
            entry["change"] = "new"
            counts["new_hosts"] += 1
        elif hb is None:
            entry["change"] = "gone"
            counts["gone_hosts"] += 1
        pa = {(p["protocol"], p["portid"]): p for p in (ha or {}).get("ports", [])}
        pb = {(p["protocol"], p["portid"]): p for p in (hb or {}).get("ports", [])}
        for pk in sorted(set(pa) | set(pb), key=lambda k: (k[0], k[1])):
            x, y = pa.get(pk), pb.get(pk)
            row = {"protocol": pk[0], "port": pk[1],
                   "before": {"state": x["state"], "service": _svc_label(x)} if x else None,
                   "after": {"state": y["state"], "service": _svc_label(y)} if y else None}
            was_open = bool(x) and x["state"] == "open"
            is_open = bool(y) and y["state"] == "open"
            if is_open and not was_open:
                row["change"] = "opened"
                counts["opened"] += 1
            elif was_open and not is_open:
                row["change"] = "closed"
                counts["closed"] += 1
            elif x and y and x["state"] != y["state"]:
                row["change"] = "state"
                counts["changed"] += 1
            elif x and y and _svc_label(x) != _svc_label(y):
                row["change"] = "service"
                counts["changed"] += 1
            elif x and y:
                continue
            else:
                row["change"] = "listed" if y else "unlisted"
                counts["changed"] += 1
            entry["ports"].append(row)
        if entry["change"] != "same" or entry["ports"]:
            hosts.append(entry)
    return {"old": _brief(old), "new": _brief(new), "same_options": old.get("args") == new.get("args"),
            "counts": counts, "hosts": hosts}


def _addr_sort(addr):
    parts = addr.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, [int(p) for p in parts])
    return (1, addr)


def _brief(rec):
    return {k: rec.get(k) for k in ("id", "started", "command", "status", "hosts_up", "open_ports")}


REPORT_CSS = """
:root { --bg:#F6F7F9; --panel:#FFF; --line:#D6DCE5; --ink:#18202D; --ink2:#4B5567; --ink3:#7A8597;
  --ok:#1E7F48; --oks:#DFF2E6; --warn:#9A6200; --warns:#FAEFD7; --accent:#2352C4; }
@media (prefers-color-scheme: dark) { :root { --bg:#0E1219; --panel:#161C26; --line:#2A3343; --ink:#E3E8F0;
  --ink2:#A8B3C3; --ink3:#7B879A; --ok:#55C487; --oks:#13301F; --warn:#E2A93E; --warns:#33270F; --accent:#7FA1FF; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 "IBM Plex Sans","Noto Sans","DejaVu Sans",system-ui,sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 24px 16px 48px; display:flex; flex-direction:column; gap:16px; }
h1 { font-size: 24px; margin: 0; } h2 { font-size: 18px; margin: 0 0 4px; } p { margin: 0; }
code, pre, .mono { font-family: "JetBrains Mono","DejaVu Sans Mono",ui-monospace,monospace; font-size: 12.5px; }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px 16px; display:flex; flex-direction:column; gap:10px; }
.kv { display:grid; grid-template-columns:auto 1fr; gap:4px 14px; } .kv dt { color:var(--ink3); } .kv dd { margin:0; overflow-wrap:anywhere; }
.wrap { overflow-x:auto; } table { width:100%; border-collapse:collapse; }
th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.07em; color:var(--ink3); padding:6px 10px; border-bottom:1px solid var(--line); }
td { padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
.st { padding:1px 7px; border-radius:4px; font-size:12px; white-space:nowrap; }
.st.open { background:var(--oks); color:var(--ok); } .st.filtered, .st.openf { background:var(--warns); color:var(--warn); }
.note { color:var(--ink2); font-size:13px; } .muted { color:var(--ink3); }
pre { margin:6px 0 0; white-space:pre-wrap; overflow-wrap:anywhere; color:var(--ink2); }
.legal { font-size:12.5px; color:var(--ink2); border-left:3px solid var(--warn); padding:2px 0 2px 10px; }
"""


def render_report(rec):
    """A self-contained HTML page for one saved scan. Every value is escaped."""
    e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
    hosts = [h for h in rec.get("hosts", []) if h.get("status") == "up"]
    title = "Nmap report - " + ", ".join(rec.get("targets") or []) if rec.get("targets") else "Nmap report"
    parts = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
             "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
             "<title>%s</title><style>%s</style></head><body><main>" % (e(title), REPORT_CSS),
             "<div><h1>%s</h1><p class=\"muted\">Made with Ariadne</p></div>" % e(title),
             "<section class=\"panel\"><dl class=\"kv\">",
             "<dt>Command</dt><dd><code>%s</code></dd>" % e(rec.get("command")),
             "<dt>Started</dt><dd>%s</dd>" % e(rec.get("started")),
             "<dt>Duration</dt><dd>%s s</dd>" % e(rec.get("elapsed")),
             "<dt>Result</dt><dd>%s</dd>" % e(rec.get("summary") or rec.get("status")),
             "<dt>Nmap</dt><dd>%s</dd>" % e(rec.get("nmap_version")),
             "</dl></section>"]
    if rec.get("status") != "done":
        parts.append("<p class=\"legal\">This scan did not finish (%s), so the results may be incomplete.</p>" % e(rec.get("status")))
    if not hosts:
        parts.append("<section class=\"panel\"><p>No host answered.</p></section>")
    for h in hosts:
        name = (h.get("hostnames") or [""])[0]
        addr = host_key(h)
        parts.append("<section class=\"panel\"><div><h2>%s</h2><p class=\"mono muted\">%s</p></div>"
                     % (e(name or addr), e(addr + (" - " + h["mac"] if h.get("mac") else ""))))
        facts = [("OS guess", h.get("os")), ("Hardware", h.get("vendor")),
                 ("Not shown", ", ".join("%s %s" % (x.get("count"), x.get("state")) for x in h.get("extraports", [])))]
        facts = [(k, v) for k, v in facts if v]
        if facts:
            parts.append("<dl class=\"kv\">" + "".join("<dt>%s</dt><dd>%s</dd>" % (e(k), e(v)) for k, v in facts) + "</dl>")
        if h.get("ports"):
            parts.append("<div class=\"wrap\"><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>What it means</th></tr></thead><tbody>")
            for p in h["ports"]:
                st = p.get("state", "")
                cls = "openf" if st == "open|filtered" else st
                scripts = "".join("<pre>%s: %s</pre>" % (e(s.get("id")), e((s.get("output") or "").strip()))
                                  for s in p.get("scripts", []))
                parts.append("<tr><td class=\"mono\">%s/%s</td><td><span class=\"st %s\">%s</span></td><td>%s</td><td class=\"note\">%s%s</td></tr>"
                             % (e(p.get("portid")), e(p.get("protocol")), e(cls), e(st), e(_svc_label(p)),
                                e(p.get("note") or ""), scripts))
            parts.append("</tbody></table></div>")
        else:
            parts.append("<p class=\"muted\">No ports listed for this host.</p>")
        parts.append("</section>")
    parts.append("<p class=\"legal\">Only scan networks and machines you own or have written permission to test.</p>")
    parts.append("</main></body></html>")
    return "".join(parts)


# --------------------------------------------------------------------------
# Plain-language hints for nmap messages that confuse beginners
# --------------------------------------------------------------------------

HINTS = [
    (re.compile(r'Failed to resolve "(.+?)"'),
     'Nmap could not find the name "{0}". Check the spelling, or use the IP address instead.'),
    (re.compile(r"Idle scan zombie .* cannot be used"),
     "The zombie host for the idle scan (-sI) is not usable: its IP ID counter is not predictable, "
     "which is true of most modern systems. Try an older, quiet device (some printers work) or another scan type."),
    (re.compile(r"FTP bounce|bounce server"),
     "The FTP server refused to relay the scan (-b). Almost every modern FTP server blocks this; "
     "it only works with very old servers."),
    (re.compile(r"failed to determine route"),
     "Nmap found no network route to the target. With -S (spoofed source) also choose the interface with -e, "
     "and use a source address that belongs to that network."),
    (re.compile(r"requires root privileges|requested a scan type which requires root"),
     "This option needs raw packet access, which Nmap does not have as a normal user. Run the setcap "
     "command shown in Setup once. For a plain port scan, TCP Connect scan (-sT) works without it."),
    (re.compile(r"Failed to open device|Could not find interface|unable to find interface", re.I),
     "The network interface given with -e does not exist on this machine. Pick one from the list in Setup."),
    (re.compile(r"Note: Host seems down"),
     "Nmap thinks the host is offline because it did not answer the discovery probes. "
     "If you know it is on, try Skip discovery (-Pn)."),
    # nmap 7.99 aborts here when it looks up names with a spoofed source (-S).
    (re.compile(r"resolve_nsock\(\).*Assertion|massdns.*Assertion"),
     "Nmap crashed while looking up host names. This is a bug in this Nmap version, not in your options. "
     "Adding -n (Never do DNS resolution) avoids it."),
    # The Nmap 7.992 package on Arch Linux rejects every value for these.
    (re.compile(r"--(top-ports|port-ratio) should be"),
     "If the value you gave is correct, this Nmap build has a known problem with --{0} "
     "(seen with Nmap 7.992 on Arch Linux). Use Fast scan (-F) or list the ports with -p instead."),
]


def crash_hint(code):
    # A negative code on Linux and macOS means nmap was killed by a signal.
    if code >= 0:
        return None
    try:
        name = signal.Signals(-code).name
    except ValueError:
        name = "signal %d" % -code
    return ("Nmap itself crashed (%s). This is a bug in the installed Nmap, not a mistake in your options. "
            "Run the scan again; if it keeps happening, remove the last option you added or update Nmap." % name)


def hint_for(line):
    for rx, text in HINTS:
        m = rx.search(line)
        if m:
            return text.format(*m.groups())
    return None


# --------------------------------------------------------------------------
# Scan runner (one at a time)
# --------------------------------------------------------------------------

class Runner:
    def __init__(self, history):
        self.proc = None
        self.lock = threading.Lock()
        self.history = history

    def stop(self):
        with self.lock:
            p = self.proc
        if p and p.poll() is None:
            p.nav_stopped = True
            try:
                p.terminate()
            except Exception:
                pass

    def run(self, argv, targets, privileged, emit):
        """Spawn nmap, push SSE events through emit(event, obj), then save the scan."""
        path = nmap_path()
        if not path:
            emit("error", {"message": "nmap is not installed or not on PATH."})
            return
        # On Linux/macOS the XML goes through its own pipe, so stdout keeps nmap's
        # normal text (what -v, -d and --packet-trace print) for the terminal view.
        # Windows has no /dev/fd, so there XML uses stdout and that text is lost.
        xml_r = xml_w = None
        if os.name == "posix" and os.path.isdir("/dev/fd"):
            xml_r, xml_w = os.pipe()
            xml_out = "/dev/fd/%d" % xml_w
        else:
            xml_out = "-"
        # --noninteractive + closed stdin: nmap must never wait for keypresses.
        cmd = [path] + argv + ["-oX", xml_out, "--stats-every", "2s", "--noninteractive"]
        if privileged and "--privileged" not in cmd:
            cmd.append("--privileged")

        # If the page goes away, stop nmap but still save what it found.
        client_gone = threading.Event()

        def send(event, obj):
            if client_gone.is_set():
                return
            try:
                emit(event, obj)
            except OSError:  # BrokenPipe, ConnectionReset/Aborted
                client_gone.set()
                self.stop()

        record = {"id": self.history.new_id(), "version": 1, "started": time.strftime("%Y-%m-%d %H:%M:%S"),
                  "args": argv, "targets": targets,
                  "command": "nmap " + " ".join('"%s"' % a if " " in a else a for a in argv),
                  "nmap_version": "", "status": "", "exit_code": None, "summary": "", "elapsed": "",
                  "hosts_up": 0, "open_ports": 0, "hosts": []}
        t0 = time.time()
        send("start", {"cmd": " ".join(cmd), "argv": cmd, "stdout": xml_r is not None})
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, bufsize=0,
                                    pass_fds=(xml_w,) if xml_w is not None else ())
        except Exception as e:
            if xml_r is not None:
                os.close(xml_r)
                os.close(xml_w)
            send("error", {"message": "Could not start nmap: %s" % e})
            return
        if xml_w is not None:
            os.close(xml_w)  # nmap holds the write end now; EOF arrives when it exits
            xml_src = os.fdopen(xml_r, "rb", buffering=0)
        else:
            xml_src = proc.stdout
        proc.nav_stopped = False
        with self.lock:
            self.proc = proc

        # Drain stderr (warnings, errors) and, with the XML pipe, stdout (normal
        # output) in the background.
        stderr_lines = []
        hints_sent = set()

        def hint(text):
            if text and text not in hints_sent:
                hints_sent.add(text)
                send("hint", {"text": text})

        def drain(stream, event, keep):
            for raw in iter(stream.readline, b""):
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line:
                    if keep is not None:
                        keep.append(line)
                    send(event, {"line": line})
                    hint(hint_for(line))
        drains = [threading.Thread(target=drain, args=(proc.stderr, "stderr", stderr_lines), daemon=True)]
        if xml_src is not proc.stdout:
            drains.append(threading.Thread(target=drain, args=(proc.stdout, "stdout", None), daemon=True))
        for th in drains:
            th.start()

        parser = ET.XMLPullParser(["start", "end"])
        root = None
        xml_buf = bytearray()
        parsing = True
        try:
            while True:
                chunk = xml_src.read(4096)
                if not chunk:
                    if proc.poll() is not None:
                        break
                    continue
                xml_buf += chunk
                if not parsing:
                    continue
                try:
                    parser.feed(chunk)
                    events = list(parser.read_events())
                except ET.ParseError:
                    parsing = False  # keep the raw XML; stop interpreting it
                    continue
                for ev, el in events:
                    if ev == "start" and el.tag == "nmaprun" and root is None:
                        root = el
                        record["nmap_version"] = el.get("version", "")
                        send("run", {"args": el.get("args", ""), "start": el.get("startstr", ""),
                                     "scanner": el.get("scanner", ""), "version": el.get("version", "")})
                    elif ev == "end" and el.tag == "taskprogress":
                        send("progress", {"task": el.get("task", ""), "percent": float(el.get("percent", "0") or 0),
                                          "remaining": el.get("remaining", ""), "etc": el.get("etc", "")})
                    elif ev == "end" and el.tag == "taskbegin":
                        send("task", {"task": el.get("task", ""), "phase": "begin"})
                    elif ev == "end" and el.tag == "taskend":
                        send("task", {"task": el.get("task", ""), "phase": "end", "extrainfo": el.get("extrainfo", "")})
                    elif ev == "end" and el.tag == "hosthint":
                        send("hosthint", parse_host(el))
                    elif ev == "end" and el.tag == "host":
                        h = parse_host(el)
                        record["hosts"].append(h)
                        send("host", h)
                        el.clear()
                        if root is not None:
                            root.clear()
                    elif ev == "end" and el.tag == "finished":
                        record["summary"] = el.get("summary", "")
                        record["elapsed"] = el.get("elapsed", "")
                        send("finished", {"time": el.get("timestr", ""), "elapsed": el.get("elapsed", ""),
                                          "summary": el.get("summary", ""), "exit": el.get("exit", "")})
        finally:
            for th in drains:
                th.join(timeout=1)
            if xml_src is not proc.stdout:
                xml_src.close()

        code = proc.wait()
        with self.lock:
            if self.proc is proc:  # a newer scan may already own the slot
                self.proc = None
        if proc.nav_stopped:
            record["status"] = "stopped"
        elif code != 0:
            record["status"] = "error"
            hint(crash_hint(code))
            send("error", {"message": "nmap exited with code %d." % code,
                           "stderr": "\n".join(stderr_lines[-5:])})
        else:
            record["status"] = "done"
        record["exit_code"] = code
        record["elapsed"] = record["elapsed"] or "%.2f" % (time.time() - t0)
        record["hosts_up"] = sum(1 for h in record["hosts"] if h.get("status") == "up")
        if code == 0 and not record["hosts_up"] and "-sL" not in argv:
            if "--spoof-mac" in argv:
                hint("No host answered. With --spoof-mac the replies are sent to the fake hardware address, "
                     "so on the local network Nmap usually never sees them.")
            elif "-S" in argv:
                hint("No host answered. With -S the replies go to the spoofed address, not to you, "
                     "so Nmap cannot see them unless it can watch that address's traffic.")
        record["open_ports"] = sum(1 for h in record["hosts"] for p in h.get("ports", []) if p.get("state") == "open")
        try:
            self.history.save(record, xml_buf)
            send("saved", {"id": record["id"]})
        except OSError as e:
            send("stderr", {"line": "Ariadne could not save this scan: %s" % e})
        send("done", {"code": code})


RUNNER = Runner(HISTORY)


# --------------------------------------------------------------------------
# Request guard
# --------------------------------------------------------------------------

def request_problem(method, path, headers, port):
    """Why this request must be refused, or None if it may go ahead.

    The server only listens on 127.0.0.1, but any web page open in the same
    browser can still send requests to it. These checks keep them out:
      * Host must be our own address (blocks DNS rebinding).
      * On /api, Origin / Sec-Fetch-Site, when the browser sends them, must be
        ours. The page itself may be opened from a link on another site; it
        cannot be framed (frame-ancestors) and its token cannot be read.
      * /api needs the per-run token, sent in a custom header. A foreign page
        does not know it, and a custom header forces a CORS preflight that
        this server never approves.
      * POST bodies must be JSON, so a plain HTML form cannot post them.
    """
    ours = {"127.0.0.1:%d" % port, "localhost:%d" % port}
    if headers.get("Host", "") not in ours:
        return "Unexpected Host header. Open the app at http://127.0.0.1:%d" % port
    if path.startswith("/api/"):
        origin = headers.get("Origin")
        if origin is not None and origin not in {"http://" + h for h in ours}:
            return "Requests from other web pages are not allowed."
        if headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            return "Requests from other web pages are not allowed."
        if not hmac.compare_digest(headers.get(TOKEN_HEADER, "").encode(), TOKEN.encode()):
            return "Missing or wrong session token. Reload the page."
        if method == "POST" and not headers.get("Content-Type", "").startswith("application/json"):
            return "Requests must be sent as JSON."
    return None


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------

HISTORY_ROUTE = re.compile(r"^/api/history/([^/]+)(?:/(xml|report))?$")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # stream until close; simplest for SSE

    def log_message(self, fmt, *a):
        pass  # keep the console quiet

    def _security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")

    def _send(self, code, body, ctype="application/json", filename=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % filename)
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _allowed(self):
        problem = request_problem(self.command, urlsplit(self.path).path, self.headers,
                                  self.server.server_address[1])
        if problem:
            self._send(403, {"error": problem})
            return False
        return True

    def do_GET(self):
        if not self._allowed():
            return
        url = urlsplit(self.path)
        if url.path in ("/", "/index.html"):
            try:
                with open(INDEX, "rb") as f:
                    data = f.read()
            except OSError:
                self._send(500, "<h1>index.html not found next to app.py</h1>", "text/html")
                return
            meta = ('<meta name="navigator-token" content="%s">\n' % TOKEN).encode("ascii")
            self._send(200, meta + data, "text/html; charset=utf-8")
            return
        if url.path == "/api/env":
            self._send(200, env_payload())
            return
        if url.path == "/api/history":
            self._send(200, HISTORY.list())
            return
        if url.path == "/api/diff":
            q = parse_qs(url.query)
            old, new = HISTORY.get(q.get("a", [""])[0]), HISTORY.get(q.get("b", [""])[0])
            if not old or not new:
                self._send(404, {"error": "One of the scans was not found."})
                return
            if old["id"] > new["id"]:
                old, new = new, old
            self._send(200, diff_scans(old, new))
            return
        m = HISTORY_ROUTE.match(url.path)
        if m:
            sid, kind = m.group(1), m.group(2)
            rec = HISTORY.get(sid)
            if not rec:
                self._send(404, {"error": "Scan not found."})
            elif kind == "xml":
                self._send(200, HISTORY.xml(sid) or b"", "application/xml", "nmap-%s.xml" % sid)
            elif kind == "report":
                self._send(200, render_report(rec), "text/html; charset=utf-8", "nmap-report-%s.html" % sid)
            else:
                self._send(200, rec)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._allowed():
            return
        path = urlsplit(self.path).path
        if path == "/api/stop":
            RUNNER.stop()
            self._send(200, {"stopped": True})
            return
        if path == "/api/scan":
            self._scan()
            return
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._allowed():
            return
        m = HISTORY_ROUTE.match(urlsplit(self.path).path)
        if m and not m.group(2):
            if HISTORY.delete(m.group(1)):
                self._send(200, {"deleted": True})
            else:
                self._send(404, {"error": "Scan not found."})
            return
        self._send(404, {"error": "not found"})

    def _scan(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
            args = payload.get("args", [])
            argv, targets = validate(args)
        except ValidationError as e:
            self._send(400, {"error": str(e)})
            return
        except Exception as e:
            self._send(400, {"error": "Bad request: %s" % e})
            return

        # One scan at a time.
        RUNNER.stop()

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self._security_headers()
        self.end_headers()

        lock = threading.Lock()

        def emit(event, obj):
            msg = "event: %s\ndata: %s\n\n" % (event, json.dumps(obj))
            with lock:
                self.wfile.write(msg.encode("utf-8"))
                self.wfile.flush()

        priv = env_payload()["privileged"]
        RUNNER.run(argv, targets, priv, emit)


# --------------------------------------------------------------------------
# Self-test (no nmap needed) and entry point
# --------------------------------------------------------------------------

def selftest():
    ok = [
        ["-sS", "-p 22,80,443", "-T4", "scanme.nmap.org"],
        ["-sn", "192.168.1.0/24"],
        ["-A", "--script=http-title,ssh-hostkey", "127.0.0.1"],
        ["-sU", "-sS", "--top-ports", "50", "-PS80,443", "10.0.0.1"],
        ["--min-rate", "300", "-6", "2001:db8::1"],
        ["-sn", "--exclude 192.168.1.1,192.168.1.73", "192.168.1.0/24"],
        ["-sL", "-n", "-iR 3"],
        ['--data-string "authorized test"', "-p 22, 80", "10.0.0.1"],
    ]
    bad = [
        (['--data-string "a; reboot"', "10.0.0.1"], "metacharacter in free text"),
        (["-p 22 80", "10.0.0.1"], "space inside a port list"),
        (["-sS", "127.0.0.1; rm -rf /"], "metacharacter"),
        (["-oN", "/etc/passwd", "127.0.0.1"], "disabled file flag"),
        (["--totally-made-up", "127.0.0.1"], "unknown flag"),
        (["-sS"], "no target"),
        (["-iL", "hosts.txt"], "file read disabled"),
    ]
    print("index.html present:", os.path.exists(INDEX))
    print("\nshould PASS:")
    allgood = True
    for a in ok:
        try:
            argv, tg = validate(a)
            print("  ok  ", a, "->", " ".join(argv))
        except ValidationError as e:
            allgood = False
            print("  FAIL", a, "->", e)
    print("\nshould be REFUSED:")
    for a, why in bad:
        try:
            validate(a)
            allgood = False
            print("  LEAK", a, "(%s) was accepted!" % why)
        except ValidationError as e:
            print("  rej ", a, "->", e)
    def check(label, cond):
        nonlocal allgood
        print("  %s  %s" % ("ok  " if cond else "FAIL", label))
        allgood = allgood and bool(cond)

    print("\nfree text and lists:")
    argv, _ = validate(['--data-string "authorized test"', "-p 22, 80", "10.0.0.1"])
    check("--data-string keeps its spaces as one argument", "authorized test" in argv)
    check("'22, 80' becomes '22,80'", "22,80" in argv and "80" not in argv)
    check("hint for an unknown name", "typo.example" in (hint_for('Failed to resolve "typo.example".') or ""))
    check("hint for the 7.99 DNS crash", "-n" in (hint_for("nmap: massdns.cc:763: bool DNS::ResolverImpl::resolve_nsock(): "
                                                           "Assertion `new_reqs.empty()' failed.") or ""))
    check("hint for a rejected --top-ports", "-F" in (hint_for("--top-ports should be an integer between 1 and 65535") or ""))
    check("hint when nmap crashes", "SIGSEGV" in (crash_hint(-11) or "") and crash_hint(1) is None)

    print("\nrequest guard:")
    good = {"Host": "127.0.0.1:8732", TOKEN_HEADER: TOKEN, "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8732", "Sec-Fetch-Site": "same-origin"}
    bad_cases = [
        ("no token", {k: v for k, v in good.items() if k != TOKEN_HEADER}),
        ("wrong token", dict(good, **{TOKEN_HEADER: "nope"})),
        ("foreign Origin", dict(good, Origin="https://evil.example")),
        ("cross-site fetch", dict(good, **{"Sec-Fetch-Site": "cross-site"})),
        ("rebinding Host", dict(good, Host="evil.example:8732")),
        ("form post (text/plain)", dict(good, **{"Content-Type": "text/plain"})),
    ]
    check("own page, own token, JSON is allowed", request_problem("POST", "/api/scan", good, 8732) is None)
    for label, hdrs in bad_cases:
        check("%s is refused" % label, request_problem("POST", "/api/scan", hdrs, 8732) is not None)
    check("page opened from a link elsewhere is allowed",
          request_problem("GET", "/", {"Host": "localhost:8732", "Sec-Fetch-Site": "cross-site"}, 8732) is None)
    check("page via a rebinding Host is refused", request_problem("GET", "/", {"Host": "evil.example:8732"}, 8732) is not None)

    print("\nparser, notes, history, diff, report:")
    fixture = lambda ports: ('<nmaprun><host><status state="up" reason="syn-ack"/>'
                             '<address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="box.lan" type="PTR"/></hostnames>'
                             '<ports><extraports state="closed" count="997"/>' + ports + "</ports></host></nmaprun>")
    p22 = ('<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>'
           '<service name="ssh" product="OpenSSH" version="9.6p1" method="probed"/></port>')
    p80 = ('<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" method="table"/>'
           '<script id="http-title" output="&lt;script&gt;alert(1)&lt;/script&gt;"/></port>')
    p80c = '<port protocol="tcp" portid="80"><state state="filtered" reason="no-response"/><service name="http" method="table"/></port>'
    p3306 = '<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/><service name="mysql" method="table"/></port>'
    old_h = [parse_host(h) for h in ET.fromstring(fixture(p22 + p80)).iter("host")]
    new_h = [parse_host(h) for h in ET.fromstring(fixture(p22 + p80c + p3306)).iter("host")]
    check("ssh note is plain language", "SSH" in old_h[0]["ports"][0]["note"])
    check("port-table guess says to add -sV", "-sV" in old_h[0]["ports"][1]["note"])
    check("closed/filtered ports get no note", new_h[0]["ports"][1]["note"] == "")
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        hist = History(tmp)
        a = {"id": "20261026-100000-aaaa", "args": ["-F", "box.lan"], "targets": ["box.lan"], "command": "nmap -F box.lan",
             "status": "done", "hosts": old_h, "hosts_up": 1, "open_ports": 2}
        b = dict(a, id="20261026-110000-bbbb", hosts=new_h, open_ports=2)
        hist.save(a, b"<nmaprun/>")
        hist.save(b, b"<nmaprun/>")
        listed = hist.list()
        check("history lists newest first without hosts",
              [r["id"] for r in listed] == [b["id"], a["id"]] and "hosts" not in listed[0])
        check("history refuses path-like ids", hist.get("../../etc/passwd") is None and hist.xml("..\\x") is None)
        d = diff_scans(hist.get(a["id"]), hist.get(b["id"]))
        changes = {r["port"]: r["change"] for r in d["hosts"][0]["ports"]}
        check("diff: 80 closed, 3306 opened, 22 unchanged", changes == {80: "closed", 3306: "opened"})
        check("history deletes", hist.delete(a["id"]) and hist.get(a["id"]) is None)
        rep = render_report(b)
        check("report escapes script output", "<script>alert" not in render_report(a) and "&lt;script&gt;" in render_report(a))
        check("report shows the notes", "MySQL" in rep)

    print("\nenvironment:")
    print(" ", json.dumps(env_payload()))
    print("\nSELFTEST", "OK" if allgood else "HAD FAILURES")
    return 0 if allgood else 1


def main():
    global HISTORY, RUNNER
    ap = argparse.ArgumentParser(description="Ariadne local backend")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--bind", default=os.environ.get("ARIADNE_BIND", "127.0.0.1"),
                    help="address to listen on (default 127.0.0.1). Only change it inside a "
                         "container whose port is published to the host's loopback")
    ap.add_argument("--open", action="store_true", help="open the app in the default browser")
    ap.add_argument("--data-dir", default=None, help="where saved scans go (default: %s)" % default_data_dir())
    ap.add_argument("--selftest", action="store_true", help="check the arg checker, parser and guards, then exit")
    ap.add_argument("--version", action="version", version="Ariadne " + APP_VERSION)
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if args.data_dir:
        HISTORY = History(os.path.abspath(args.data_dir))
        RUNNER = Runner(HISTORY)

    url = "http://127.0.0.1:%d" % args.port
    try:
        httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    except OSError as e:
        if e.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1)):
            print("Port %d is already in use. Ariadne may already be running at %s" % (args.port, url))
            print("Or start it on another port: python3 app.py --port 9000")
            if args.open:
                webbrowser.open(url)
            sys.exit(1)
        raise

    env = env_payload()
    print("Ariadne " + APP_VERSION)
    print("  nmap:", env["path"] or "NOT FOUND - install it first (e.g. sudo apt install nmap)")
    if env["found"]:
        print("  version:", env["version"], "| privileged:", env["privileged"], "(%s)" % env["privilege_note"])
    print("  scans saved in:", HISTORY.path)
    if args.bind not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING: listening on %s, not only on loopback. Do this only inside a container." % args.bind)
    print("  open:  " + url)
    print("  (Ctrl+C to stop)")
    if args.open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
        RUNNER.stop()
        httpd.shutdown()


if __name__ == "__main__":
    main()
