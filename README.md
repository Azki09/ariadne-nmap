# Ariadne

**A friendly guide to Nmap.**

In the Greek myth, Ariadne gave Theseus a thread to find his way through the
labyrinth. Nmap has more than a hundred options; this is the thread.

A friendly way to learn and use [Nmap](https://nmap.org). Pick what you want to
do, see the exact command it builds and what every option means, run the scan
with the Nmap on your computer, and read the results in plain words.

Made for people who are new to network scanning. Experts can switch to Expert
mode and type commands directly.

> **Scan only networks and machines you own or have written permission to
> test.** Scanning other people's systems can be illegal where you live.

## What you get

- A command builder with an explanation for each Nmap option, and warnings for
  options that will not work together or need extra permissions.
- Live results while the scan runs: hosts, open ports and services.
- The Terminal tab, with Nmap's own text output.
- The Packets tab, which shows the packets sent and received for each port
  when `--packet-trace` is on.
- A "What this means" box when Nmap stops with an error.
- A history of your scans, saved on your computer, which you can reopen and
  compare.

## Requirements

- **Nmap**, installed separately. Ariadne does not include Nmap.
- **Python 3.8 or newer.** Nothing else to install: no pip packages, no build.
- A web browser.

## Install and run (Linux)

1. Install Nmap and Python with your package manager:

   ```
   sudo apt install nmap python3        # Debian, Ubuntu, Kali, Mint
   sudo dnf install nmap python3        # Fedora
   sudo pacman -S nmap python           # Arch
   sudo zypper install nmap python3     # openSUSE
   ```

2. Download this project and start it:

   ```
   git clone https://github.com/Azki09/ariadne-nmap.git
   cd ariadne-nmap/prototype
   ./start.sh
   ```

   Your browser opens at `http://127.0.0.1:8732`. Keep the terminal open while
   you use the app; closing it stops the app.

3. Optional: add it to your applications menu with `./start.sh --install`.

The first time, the **Getting started** guide on the Start screen checks your
setup, gives you the exact commands for anything missing, and runs a safe
first scan of your own computer.

### Letting Nmap send raw packets

Many scan types (SYN scan, OS detection, UDP scan) need raw network access,
which normal users do not have. Instead of running everything as root, give
that permission to Nmap once:

```
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
```

Reload the page and the pill at the top changes from **Normal user** to
**Privileged**. Without it, the app still works: it tells you which options
need it, and the TCP Connect scan (`-sT`) works without it.

## Platforms

| Platform | Status |
|----------|--------|
| Linux    | Supported. Tested on Ubuntu 20.04 to 24.04, Debian 12, Fedora 41, Arch, openSUSE Tumbleweed, Alpine 3.20 and Kali, with Nmap 7.80 to 7.99. |
| Windows  | Experimental. Scans work with Nmap and Npcap installed, but the Terminal tab cannot show Nmap's own output and the Packets tab shows an example instead of real packets. |
| macOS    | Experimental. Not tested yet. |

## Security

Ariadne runs a small server on your computer that only your browser can
reach:

- It listens on `127.0.0.1` only, never on your network.
- It starts Nmap with a list of arguments, never through a shell, so a target
  or option cannot run other commands.
- It accepts only Nmap options it knows, and refuses the options that save
  to files or read lists from files (the app saves each scan itself).
- Every request must carry a secret that only its own page receives, so other
  web sites open in your browser cannot start scans.

Found a security problem? Please open an issue without the details and ask for
a private contact, or write to the author through GitHub.

## Options

```
python3 app.py --port 9000      use another port
python3 app.py --data-dir DIR   where to save scans
python3 app.py --selftest       check the app without running Nmap
python3 app.py --version        show the version
```

## Tests

See [tests/README.md](tests/README.md). The tests use a Docker lab with
practice targets, so nothing outside your computer is scanned.

Hail the Omnissiah!

## License

MIT, see [LICENSE](LICENSE). Nmap itself is not part of this project and has
its own license; see [NOTICE](NOTICE).
