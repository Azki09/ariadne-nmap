#!/usr/bin/env python3
"""Run every Ariadne option against the Docker lab through /api/scan.

Args are sent the way the page sends them ("flag value" strings).
Run inside the navigator container (see tests/README.md):
    python3 options_test.py [base_url] [filter]
"""
import json, re, sys, time, threading, urllib.request, urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8732"
FILTER = sys.argv[2] if len(sys.argv) > 2 else ""
PORTS = "-p 21,22,53,80,6379,8888"
ALL = ["172.30.0.20", "172.30.0.30", "172.30.0.40"]
WEB, SVC = ["172.30.0.20"], ["172.30.0.40"]

page = urllib.request.urlopen(BASE + "/").read().decode()
TOKEN = re.search(r'token" content="([^"]+)"', page).group(1)
HDR = {"X-Ariadne-Token": TOKEN, "Origin": BASE, "Content-Type": "application/json"}

# (category, name, args, expect)  expect: "ok" | "refused" | "stop:N" (stop after N s)
#   | "hint" | "hint-if-empty" | "ok-or-hint" | "stdout~regex" (see verdict())
C = []
def t(cat, name, args, expect="ok"):
    C.append((cat, name, args, expect))

# target
t("target", "IP list", [PORTS] + ALL, "stdout~^Nmap scan report for")
t("target", "typo in a name", [PORTS, "web", "no-such-host.invalid"], "hint")
t("target", "hostnames", [PORTS, "web", "cache", "services"])
t("target", "CIDR", ["-sn", "172.30.0.0/24"])
t("target", "dash range", ["-sn", "172.30.0.18-42"])
t("target", "-iL", ["-iL hosts.txt"], "refused")
t("target", "-iR (UI: no target)", ["-sL", "-n", "-iR 3"])
t("target", "--exclude", ["-sn", "--exclude 172.30.0.30", "172.30.0.0/24"])
t("target", "--excludefile", ["-sn", "--excludefile skip.txt", "172.30.0.0/24"], "refused")
# discovery
t("discovery", "-sL", ["-sL", "172.30.0.16/28"])
t("discovery", "-sn", ["-sn"] + ALL)
t("discovery", "-Pn", ["-Pn", PORTS] + ALL)
t("discovery", "-PS bare", ["-sn", "-PS"] + ALL)
t("discovery", "-PS ports", ["-sn", "-PS21,22,80"] + ALL)
t("discovery", "-PA", ["-sn", "-PA80"] + ALL)
t("discovery", "-PU", ["-sn", "-PU53"] + ALL)
t("discovery", "-PY", ["-sn", "-PY"] + ALL)
t("discovery", "-PE", ["-sn", "-PE"] + ALL)
t("discovery", "-PP", ["-sn", "-PP"] + ALL)
t("discovery", "-PM", ["-sn", "-PM"] + ALL)
t("discovery", "-PO list", ["-sn", "-PO1,2,4"] + ALL)
t("discovery", "-PO bare", ["-sn", "-PO"] + ALL)
t("discovery", "-n", ["-n", PORTS] + ALL)
t("discovery", "-R", ["-R", "-sL", "172.30.0.16/28"])
t("discovery", "--dns-servers", ["--dns-servers 172.30.0.40", "-sL", "web.lab.test", "172.30.0.20"])
t("discovery", "--system-dns", ["--system-dns", PORTS, "web", "services"])
t("discovery", "--traceroute", ["--traceroute", PORTS] + ALL)
# techniques
for f in ["-sS", "-sT", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX"]:
    t("technique", f, [f, PORTS] + ALL)
t("technique", "--scanflags", ["--scanflags SYNFIN", PORTS] + ALL)
t("technique", "-sI idle", ["-sI 172.30.0.30", "-Pn", "-p 80,22", "172.30.0.40"], "hint")
t("technique", "-b ftp bounce", ["-b anonymous@172.30.0.40:21", "-Pn", "-p 80", "172.30.0.20"], "hint")
t("technique", "-sU", ["-sU", "-p 53,161,123"] + SVC)
t("technique", "-sU -sS mixed ports", ["-sS", "-sU", "-p U:53,161,T:22,80"] + ALL)
t("technique", "-sY", ["-sY", "-p 80,2905"] + ALL)
t("technique", "-sZ", ["-sZ", "-p 80,2905"] + ALL)
t("technique", "-sO", ["-sO", "-p 1,6,17,132"] + ALL)
# ports
t("ports", "-F", ["-F"] + ALL)
t("ports", "--top-ports", ["--top-ports 20"] + ALL)
t("ports", "-p list", ["-p 22,80,443"] + ALL)
t("ports", "-p range", ["-p 1-1024"] + ALL)
t("ports", "-p22 attached", ["-p22"] + SVC)
t("ports", "-p-", ["-p-", "-T4", "--min-rate 5000"] + WEB)
t("ports", "--exclude-ports", ["-F", "--exclude-ports 80,22"] + ALL)
t("ports", "-r", ["-r", PORTS] + ALL)
t("ports", "--port-ratio", ["--port-ratio 0.05"] + ALL)
# detection
t("detection", "-sV", ["-sV", PORTS] + ALL)
t("detection", "--version-intensity", ["-sV", "--version-intensity 9", PORTS] + SVC)
t("detection", "--version-light", ["-sV", "--version-light", PORTS] + ALL)
t("detection", "--version-all", ["-sV", "--version-all", PORTS] + SVC)
t("detection", "--version-trace", ["-sV", "--version-trace", "-p 22,80"] + WEB, "stdout~Service scan")
# scripts
t("scripts", "-sC", ["-sC", PORTS] + ALL)
t("scripts", "--script list", ["--script=http-title,ssh-hostkey,ftp-anon,redis-info", PORTS] + ALL)
t("scripts", "--script category", ["--script=safe", "-p 21,22,80"] + SVC + WEB)
t("scripts", "--script udp", ["-sU", "--script=snmp-info,dns-recursion", "-p 53,161"] + SVC)
t("scripts", "--script-args", ["--script=http-enum", "--script-args http-enum.basepath=/", "-p 80"] + WEB)
t("scripts", "--script-args quoted", ["--script=http-title", "--script-args http.useragent=Ariadne test", "-p 80"] + WEB)
t("scripts", "--script-args-file", ["-sC", "--script-args-file args.txt", "-p 80"] + WEB, "refused")
t("scripts", "--script-trace", ["--script=http-title", "--script-trace", "-p 80"] + WEB, "stdout~NSE")
# os
t("os", "-O", ["-O", PORTS] + ALL)
t("os", "--osscan-limit", ["-O", "--osscan-limit", PORTS] + ALL)
t("os", "--osscan-guess", ["-O", "--osscan-guess", PORTS] + ALL)
# timing
t("timing", "-T0 (stopped)", ["-T0", PORTS] + WEB, "stop:8")
t("timing", "-T1 (stopped)", ["-T1", PORTS] + WEB, "stop:8")
for n in "2345":
    t("timing", "-T" + n, ["-T" + n, "-p 22,80"] + ALL)
for flag, v in [("--min-rate", "300"), ("--max-rate", "100"), ("--min-parallelism", "10"),
                ("--max-parallelism", "100"), ("--min-hostgroup", "64"), ("--max-hostgroup", "256"),
                ("--max-retries", "2"), ("--host-timeout", "30m"), ("--scan-delay", "500ms"),
                ("--max-scan-delay", "1s"), ("--initial-rtt-timeout", "100ms"),
                ("--min-rtt-timeout", "50ms"), ("--max-rtt-timeout", "1000ms")]:
    t("timing", flag, [flag + " " + v, "-p 22,80"] + ALL)
# evasion
t("evasion", "-f", ["-f", PORTS] + ALL)
t("evasion", "--mtu", ["--mtu 16", PORTS] + ALL)
t("evasion", "-D RND", ["-D RND:5", PORTS] + ALL)
t("evasion", "-D list ME", ["-D 172.30.0.91,ME,172.30.0.92", PORTS] + ALL)
# Depends on the nmap version: works (7.80), finds no route (7.94) or crashes (7.99).
t("evasion", "-S spoof", ["-S 172.30.0.99", "-e eth0", "-Pn", PORTS] + ALL, "ok-or-hint")
t("evasion", "-e", ["-e eth0", PORTS] + ALL)
t("evasion", "--source-port", ["--source-port 53", PORTS] + ALL)
t("evasion", "-g", ["-g 53", PORTS] + ALL)
t("evasion", "--proxies", ["-sT", "--proxies http://172.30.0.40:8888", "-p 80"] + WEB)
t("evasion", "--data-length", ["--data-length 25", PORTS] + ALL)
t("evasion", "--data-string (space)", ["--data-string authorized test", PORTS] + ALL)
t("evasion", "--data-string (one word)", ["--data-string authorized-test", PORTS] + ALL)
t("evasion", "--data 0x", ["--data 0xdeadbeef", PORTS] + ALL)
t("evasion", "--data (UI placeholder)", ["--data deadbeef", PORTS] + ALL)
t("evasion", "--ip-options", ["--ip-options R", PORTS] + ALL)
t("evasion", "--ttl", ["--ttl 64", PORTS] + ALL)
t("evasion", "--spoof-mac 0", ["--spoof-mac 0", PORTS] + ALL, "hint-if-empty")
t("evasion", "--spoof-mac vendor", ["--spoof-mac Cisco", PORTS] + ALL)
t("evasion", "--badsum", ["--badsum", PORTS] + ALL)
# output
t("output", "--reason", ["--reason", PORTS] + ALL)
t("output", "--open", ["--open", PORTS] + ALL)
t("output", "-v", ["-v", PORTS] + ALL, "stdout~^Discovered open port")
t("output", "-vv", ["-vv", PORTS] + ALL)
t("output", "-d", ["-d", "-p 22,80"] + WEB, "stdout~Timing report")
t("output", "-dd", ["-dd", "-p 22,80"] + WEB)
t("output", "--packet-trace", ["--packet-trace", "-p 22,80"] + WEB, "stdout~^(SENT|RCVD)")
for f in ["-oA home-scan", "-oN scan.nmap", "-oX scan.xml", "-oG scan.gnmap", "-oS scan.txt",
          "--append-output", "--stylesheet nmap.xsl", "--webxml", "--no-stylesheet", "--resume scan.nmap"]:
    t("output", f.split()[0], [f, "-p 80"] + WEB, "refused")
# misc
t("misc", "-6 address", ["-6", PORTS, "fd00:30::20", "fd00:30::40"])
t("misc", "-6 -sV -O", ["-6", "-sV", "-O", PORTS, "fd00:30::40"])
t("misc", "-A", ["-A", PORTS] + ALL)
t("misc", "--datadir", ["--datadir /tmp", "-p 80"] + WEB, "refused")
t("misc", "--send-eth", ["--send-eth", PORTS] + ALL)
t("misc", "--send-ip", ["--send-ip", PORTS] + ALL)
# goal-card style combos and malicious input
t("combo", "home check", ["-sn", "-T4", "172.30.0.0/24"])
t("combo", "full audit", ["-sS", "-sV", "-sC", "-O", "--traceroute", "--reason", "-T4", PORTS] + ALL)
t("combo", "udp+tcp all", ["-sS", "-sU", "-sV", "--top-ports 20", "--reason"] + SVC)
t("guard", "shell metachar", ["-sS", "172.30.0.20;id"], "refused")
t("guard", "unknown flag", ["--made-up", "172.30.0.20"], "refused")
t("guard", "no target", ["-sS"], "refused")


def run(cat, name, args, expect):
    body = json.dumps({"args": args}).encode()
    req = urllib.request.Request(BASE + "/api/scan", data=body, headers=HDR, method="POST")
    r = {"cat": cat, "name": name, "args": " ".join(args), "expect": expect}
    t0 = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=900)
    except urllib.error.HTTPError as e:
        r["refused"] = json.loads(e.read().decode() or "{}").get("error", str(e))
        r["secs"] = round(time.time() - t0, 1)
        return r
    stopper = None
    if expect.startswith("stop:"):
        def stop_later():
            time.sleep(int(expect[5:]))
            urllib.request.urlopen(urllib.request.Request(BASE + "/api/stop", data=b"{}", headers=HDR, method="POST"))
        stopper = threading.Thread(target=stop_later, daemon=True)
        stopper.start()
    ev = None
    events = {}
    stderr, errors, hosts, stdout, hints = [], [], [], [], []
    for raw in resp:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("event: "):
            ev = line[7:]
            events[ev] = events.get(ev, 0) + 1
        elif line.startswith("data: ") and ev:
            d = json.loads(line[6:])
            if ev == "stderr": stderr.append(d.get("line", ""))
            elif ev == "stdout": stdout.append(d.get("line", ""))
            elif ev == "hint": hints.append(d.get("text", ""))
            elif ev == "error": errors.append(d)
            elif ev == "host": hosts.append(d)
            elif ev == "done": r["code"] = d.get("code")
            elif ev == "start": r["cmd"] = d.get("cmd")
    r["secs"] = round(time.time() - t0, 1)
    r["events"] = events
    r["stderr"] = stderr
    r["stdout"] = stdout
    r["hints"] = hints
    r["errors"] = errors
    r["hosts_up"] = sum(1 for h in hosts if h.get("status") == "up")
    r["hosts"] = len(hosts)
    r["open"] = sum(1 for h in hosts for p in h.get("ports", []) if p.get("state") == "open")
    r["ports"] = sum(len(h.get("ports", [])) for h in hosts)
    r["os"] = [h["os"] for h in hosts if h.get("os")]
    r["services"] = sorted({"%s/%s %s %s" % (p["portid"], p["protocol"], p["service"].get("product", ""), p["service"].get("version", ""))
                            for h in hosts for p in h.get("ports", []) if p.get("state") == "open"})
    r["scripts"] = sorted({s["id"] for h in hosts for p in h.get("ports", []) for s in p.get("scripts", [])})
    return r


def verdict(r):
    exp = r["expect"]
    if "refused" in r:
        return "PASS" if exp == "refused" else "FAIL"
    if exp == "refused":
        return "FAIL"
    if exp.startswith("stop:"):
        return "PASS" if "saved" in r["events"] and "done" in r["events"] else "FAIL"
    if exp == "hint":  # nmap fails or finds nothing for a reason outside the app; it must be explained
        return "PASS" if r["hints"] and "saved" in r["events"] else "FAIL"
    if exp == "ok-or-hint":  # either it works, or the failure is explained
        ok = "saved" in r["events"] and ((r.get("code") == 0 and r["hosts_up"] > 0) or r["hints"])
        return "PASS" if ok else "FAIL"
    if exp == "hint-if-empty":  # results vary by network; an empty result must come with a hint
        ok = r.get("code") == 0 and "saved" in r["events"] and (r["hosts_up"] > 0 or r["hints"])
        return "PASS" if ok else "FAIL"
    if exp.startswith("stdout~"):  # nmap's own text must reach the terminal
        if not any(re.search(exp[7:], l) for l in r["stdout"]):
            return "FAIL"
    if r.get("code") != 0 or r["errors"]:
        return "FAIL"
    if "finished" not in r["events"]:
        return "FAIL"  # XML stream broken: the page never sees the end
    if "saved" not in r["events"]:
        return "FAIL"
    return "PASS"


results = []
for c in C:
    if FILTER and FILTER not in c[0] + " " + c[1]:
        continue
    r = run(*c)
    r["verdict"] = verdict(r)
    results.append(r)
    extra = r.get("refused") or "code=%s up=%s/%s open=%s out=%s %s%s" % (
        r.get("code"), r.get("hosts_up"), r.get("hosts"), r.get("open"), len(r.get("stdout", [])),
        ("ERR " + r["errors"][0]["message"] + " ") if r.get("errors") else "",
        ("HINT " + r["hints"][0][:70]) if r.get("hints") else "")
    print("%-4s %-10s %-26s %5.1fs  %s" % (r["verdict"], r["cat"], r["name"], r["secs"], extra), flush=True)

json.dump(results, open("/tmp/optest-results.json", "w"), indent=1)
fails = [r for r in results if r["verdict"] != "PASS"]
print("\n%d tests, %d failed" % (len(results), len(fails)))
