# Testing Ariadne

These tests run the app against real nmap inside the Docker lab
(`docker-compose.yml` in the project root). Scan only the lab; it is a private
network made for this.

Start the lab first:

```
docker compose up --build -d
```

## 1. Self-test (no nmap needed)

```
docker compose exec navigator python3 app.py --selftest
```

## 2. Every option against real nmap

Sends each option to `/api/scan` the way the page does and checks that nmap
runs, the results arrive and the scan is saved. Options the app does not
support yet must be refused with a clear message. About 8 minutes.

```
docker compose cp tests/options_test.py navigator:/tmp/
docker compose exec navigator python3 /tmp/options_test.py
docker compose exec navigator python3 /tmp/options_test.py http://127.0.0.1:8732 evasion   # one category
```

## 3. Normal user (nmap without capabilities)

Starts a second copy of the app on port 8733 whose nmap has no raw packet
access, the way most people run it the first time.

```
docker compose cp tests/start_normal_user.sh navigator:/tmp/
docker compose cp tests/normal_user_test.py navigator:/tmp/
docker compose exec navigator sh -c "tr -d '\r' < /tmp/start_normal_user.sh | sh"
docker compose exec navigator python3 /tmp/normal_user_test.py
```

## 4. Packet trace parser (no Docker needed)

Feeds real `--packet-trace` lines (TCP, UDP, ICMP, ARP, IPv6, CONN) to the
parser inside `index.html` and checks where each packet is filed.

```
node tests/packet_parser_test.mjs prototype/index.html
```

## 5. The page in a real browser

Drives the page in headless Edge (or Chrome via `BROWSER=...`) with clicks and
typing only, then reads the screen. Needs Node 22 or newer. Screenshots go to
the system temp folder under `ariadne-ui-test/shots`.

```
node tests/ui_test.mjs
```

On Windows, with the app running there (`python app.py --port 8790`), check the
Packets tab fallback:

```
node tests/ui_test.mjs http://127.0.0.1:8790 --windows
```

## 6. Phone and narrow windows

Opens every screen at 360 and 412 px (phone) and 480 px (narrow desktop
window), runs one small scan, and fails if anything sticks out sideways.
Screenshots go to the system temp folder under `ariadne-mobile-test`.

```
node tests/mobile_test.mjs
```

## 6a. First-run guide

Checks the "Getting started" guide in its three situations: Nmap missing,
Nmap without raw packet access, and Nmap ready. The last one is the lab; the
other two are short-lived containers built from the distribution images
(test 7) that serve the project's current files:

```
docker run -d --rm --name nn-nonmap -p 127.0.0.1:8759:8759 -e PATH=/nowhere -v "$PWD/prototype:/opt/ariadne:ro" --entrypoint /usr/bin/python3 nn-ubuntu22 app.py --port 8759
docker run -d --rm --name nn-normal --network nmap-for-dummys_lab -p 127.0.0.1:8760:8760 -v "$PWD/prototype:/opt/ariadne:ro" --entrypoint sh nn-debian12 -c 'cp /usr/bin/nmap /tmp/nmap && PATH=/tmp:$PATH exec python3 app.py --port 8760'
node tests/guide_test.mjs http://127.0.0.1:8732 http://127.0.0.1:8760 http://127.0.0.1:8759
docker rm -f nn-nonmap nn-normal
```

Start `nn-normal` fresh each time: the test runs its first scan there.

## 6b. Big scans must not freeze the page

Runs scans with tens of thousands of `--packet-trace` lines and measures how
long the page takes to answer while they stream.

```
node tests/stress_test.mjs
```

## 7. Other Linux distributions

Builds the app on several distributions, each with its own packaged nmap and
Python, and runs tests 2 and 3 on each one. Each copy joins the lab network and
listens on `127.0.0.1:<port>`, so test 5 can be pointed at it too.

| Name     | Image                  | Port |
|----------|------------------------|------|
| kali     | kalilinux/kali-rolling | 8751 |
| ubuntu22 | ubuntu:22.04           | 8752 |
| debian12 | debian:12              | 8753 |
| fedora   | fedora:41              | 8754 |
| arch     | archlinux:latest       | 8755 |
| opensuse | opensuse/tumbleweed    | 8756 |
| alpine   | alpine:3.20            | 8757 |
| ubuntu20 | ubuntu:20.04           | 8758 |

```
python tests/distros/run_distros.py build             # every image
python tests/distros/run_distros.py smoke             # self-test and one scan
python tests/distros/run_distros.py full kali arch    # every option, normal user
node tests/ui_test.mjs http://127.0.0.1:8755          # the page, on arch
```

Each nmap version writes `--packet-trace` lines a little differently (7.99
brackets the TCP header and IPv6 addresses, 7.80 has no "neighbor
advertisement" line). To check that the Packets tab reads them all:

```
tr -d '\r' < tests/distros/trace_sample.sh | docker exec -i -u root nn-kali sh | node tests/distros/trace_check.mjs prototype/index.html
```

It must report `0 not understood`.

## Known limits of the lab (not app bugs)

- `-sI` (idle scan): modern Linux hosts are not usable zombies, so nmap stops.
  The app shows an explanation.
- `-b` (FTP bounce): vsftpd refuses to relay, like almost every modern server.
- `-S` (spoofed source): nmap finds no route for an address that is not yours.
- `--spoof-mac`: sometimes no host answers, because replies go to the fake MAC.
- The Windows build cannot show nmap's own text output (`-v`, `-d`,
  `--packet-trace`) in the Terminal tab; Linux and macOS can.
