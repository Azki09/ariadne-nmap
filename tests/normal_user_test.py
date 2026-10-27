#!/usr/bin/env python3
"""Normal-user checks against a second app instance whose nmap has no capabilities.

Run inside the navigator container after tests/start_normal_user.sh.
"""
import json, re, urllib.request, urllib.error

BASE = "http://127.0.0.1:8733"
page = urllib.request.urlopen(BASE + "/").read().decode()
TOKEN = re.search(r'token" content="([^"]+)"', page).group(1)
HDR = {"X-Ariadne-Token": TOKEN, "Origin": BASE, "Content-Type": "application/json"}
ALL = ["172.30.0.20", "172.30.0.30", "172.30.0.40"]


def get(path):
    return json.loads(urllib.request.urlopen(urllib.request.Request(BASE + path, headers=HDR)).read())


def scan(args):
    req = urllib.request.Request(BASE + "/api/scan", data=json.dumps({"args": args}).encode(), headers=HDR, method="POST")
    out = {"events": [], "hosts": [], "hints": [], "stderr": [], "errors": [], "cmd": ""}
    ev = None
    for raw in urllib.request.urlopen(req, timeout=300):
        line = raw.decode().rstrip("\n")
        if line.startswith("event: "):
            ev = line[7:]; out["events"].append(ev)
        elif line.startswith("data: "):
            d = json.loads(line[6:])
            if ev == "host": out["hosts"].append(d)
            elif ev == "hint": out["hints"].append(d["text"])
            elif ev == "stderr": out["stderr"].append(d["line"])
            elif ev == "error": out["errors"].append(d)
            elif ev == "start": out["cmd"] = d["cmd"]
            elif ev == "done": out["code"] = d["code"]
    out["up"] = sum(1 for h in out["hosts"] if h["status"] == "up")
    out["open"] = sum(1 for h in out["hosts"] for p in h["ports"] if p["state"] == "open")
    return out


res = []
def check(name, cond, info=""):
    res.append(cond)
    print("%s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  -> " + str(info)[:400]))

env = get("/api/env")
check("env says not privileged", env["found"] and not env["privileged"], env)
r = scan(["-p 21,22,80,6379", "--reason"] + ALL)
check("default scan works as normal user", r.get("code") == 0 and r["up"] == 3 and r["open"] == 4 and "--privileged" not in r["cmd"], r)
r = scan(["-sT", "-sV", "-p 21,22,80"] + ALL)
check("-sT -sV works", r.get("code") == 0 and r["open"] == 3, r)
r = scan(["-sn"] + ALL)
check("-sn works", r.get("code") == 0 and r["up"] == 3, r)
r = scan(["--script=http-title,ssh-hostkey", "-p 22,80"] + ALL)
check("scripts work", r.get("code") == 0 and any(p["scripts"] for h in r["hosts"] for p in h["ports"]), r)
for flags in (["-sS"], ["-O"], ["-sU"], ["-sn", "-PE"]):
    r = scan(flags + ["-p 80", "172.30.0.20"] if flags[0] != "-sn" else flags + ["172.30.0.20"])
    check("%s as normal user fails with an explanation" % " ".join(flags),
          (r.get("code") != 0 and r["hints"]) or (r.get("code") == 0 and r["up"] == 1),
          {"code": r.get("code"), "hints": r["hints"], "stderr": r["stderr"][-3:], "up": r["up"]})
print("\n%d checks, %d failed" % (len(res), res.count(False)))
