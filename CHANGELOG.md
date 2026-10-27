# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] - unreleased

First public release.

### Added
- "Getting started" guide on the Start screen: checks that Nmap is installed
  (with the install command for your distribution), offers the exact setcap
  command for raw packets, and runs a safe first scan of your own computer.
- Works on phones and narrow windows.
- Command builder for Nmap options, in Beginner and Expert modes, with a plain
  explanation of each option and warnings for combinations that will not work.
- Live scans with the real Nmap installed on your computer: progress, hosts and
  ports appear while the scan runs.
- Results view, Terminal tab with Nmap's own output, and a Packets tab that
  shows the packets exchanged for each port when `--packet-trace` is on.
- "What this means" explanations when Nmap stops with an error.
- Scan history saved on your computer, with reopen and compare.
- Demo mode with simulated data when the app is opened without the backend.
- Linux launcher (`start.sh`) that can add the app to the applications menu.

### Security
- The backend listens on 127.0.0.1 only, never runs Nmap through a shell,
  accepts only known Nmap options and refuses requests from other web pages.
- Very large `--packet-trace` output is trimmed so the page does not freeze.

### Tested on
- Ubuntu 20.04, 22.04 and 24.04, Debian 12, Fedora 41, Arch, openSUSE
  Tumbleweed, Alpine 3.20 and Kali, with each one's own Nmap (7.80 to 7.99)
  and Python (3.8 to 3.14).
