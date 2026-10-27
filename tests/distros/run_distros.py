#!/usr/bin/env python3
"""Build Ariadne on several distributions and run the tests on each.

Needs the lab running (docker compose up -d) and Docker on the host.
    python tests/distros/run_distros.py build            build every image
    python tests/distros/run_distros.py smoke            quick check on each
    python tests/distros/run_distros.py full [names]     every option + normal user
Each app runs on the lab network and on 127.0.0.1:<port> of this computer, so
tests/ui_test.mjs can also be pointed at it: node tests/ui_test.mjs http://127.0.0.1:<port>
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NETWORK = "nmap-for-dummys_lab"
# name: (base image, lab address, port)
DISTROS = {
    "kali": ("kalilinux/kali-rolling", "172.30.0.51", 8751),
    "ubuntu22": ("ubuntu:22.04", "172.30.0.52", 8752),
    "debian12": ("debian:12", "172.30.0.53", 8753),
    "fedora": ("fedora:41", "172.30.0.54", 8754),
    "arch": ("archlinux:latest", "172.30.0.55", 8755),
    "opensuse": ("opensuse/tumbleweed", "172.30.0.56", 8756),
    "alpine": ("alpine:3.20", "172.30.0.57", 8757),
    "ubuntu20": ("ubuntu:20.04", "172.30.0.58", 8758),
}


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def build(name):
    base = DISTROS[name][0]
    r = sh(["docker", "build", "-f", "tests/distros/Dockerfile", "--build-arg", "BASE=" + base,
            "-t", "nn-" + name, "--progress=plain", "."], cwd=ROOT)
    versions = [l.split("] ", 1)[-1] for l in r.stdout.splitlines() + r.stderr.splitlines()
                if ("nmap: Nmap version" in l or "Python 3" in l) and "RUN" not in l]
    return r.returncode == 0, versions[-2:] if r.returncode == 0 else (r.stderr or r.stdout)[-1500:]


def start(name):
    _, ip, port = DISTROS[name]
    sh(["docker", "rm", "-f", "nn-" + name])
    r = sh(["docker", "run", "-d", "--name", "nn-" + name, "--network", NETWORK, "--ip", ip,
            "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", "-p", "127.0.0.1:%d:%d" % (port, port),
            "nn-" + name, "--port", str(port)])
    if r.returncode != 0:
        return False, r.stderr
    for _ in range(40):
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/" % port, timeout=2).read()
            return True, ""
        except Exception:
            time.sleep(0.5)
    return False, sh(["docker", "logs", "nn-" + name]).stdout[-1500:]


def in_container(name, *args, stdin=None):
    return sh(["docker", "exec", "-i", "nn-" + name] + list(args), input=stdin)


def copy_tests(name):
    for f in ("options_test.py", "normal_user_test.py", "start_normal_user.sh"):
        # Send bytes: text mode on Windows would turn \n back into \r\n, which sh rejects.
        data = open(os.path.join(ROOT, "tests", f), "rb").read().replace(b"\r\n", b"\n")
        subprocess.run(["docker", "exec", "-i", "nn-" + name, "sh", "-c", "cat > /tmp/" + f], input=data, capture_output=True)


def smoke(name):
    port = DISTROS[name][2]
    out = []
    r = in_container(name, "python3", "app.py", "--selftest")
    out.append("selftest " + ("OK" if "SELFTEST OK" in r.stdout else "FAILED: " + (r.stdout + r.stderr)[-600:]))
    copy_tests(name)
    r = in_container(name, "python3", "/tmp/options_test.py", "http://127.0.0.1:%d" % port, "IP list")
    out.append("scan " + ("OK" if "1 tests, 0 failed" in r.stdout else "FAILED: " + (r.stdout + r.stderr)[-800:]))
    return out


def full(name):
    port = DISTROS[name][2]
    copy_tests(name)
    r = in_container(name, "python3", "/tmp/options_test.py", "http://127.0.0.1:%d" % port)
    lines = [l for l in r.stdout.splitlines() if l.startswith("FAIL") or "tests," in l]
    in_container(name, "sh", "-c", "sh /tmp/start_normal_user.sh >/dev/null 2>&1")
    r2 = in_container(name, "python3", "/tmp/normal_user_test.py")
    lines += [l for l in r2.stdout.splitlines() if l.startswith("FAIL") or "checks," in l] or [(r2.stdout + r2.stderr)[-600:]]
    # Keep the detailed results for inspection.
    res = in_container(name, "cat", "/tmp/optest-results.json").stdout
    if res:
        open(os.path.join(os.environ.get("TEMP", "/tmp"), "distro-%s-results.json" % name), "w", encoding="utf-8").write(res)
    return lines


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "smoke"
    names = sys.argv[2:] or list(DISTROS)
    for name in names:
        if cmd == "build":
            ok, info = build(name)
            print("%-9s build %s  %s" % (name, "OK" if ok else "FAILED", info if ok else "\n" + info), flush=True)
        elif cmd in ("smoke", "full"):
            ok, err = start(name)
            if not ok:
                print("%-9s could not start: %s" % (name, err), flush=True)
                continue
            for line in (smoke(name) if cmd == "smoke" else full(name)):
                print("%-9s %s" % (name, line), flush=True)


if __name__ == "__main__":
    main()
