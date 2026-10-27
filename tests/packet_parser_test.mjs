// Pull the packet parser out of index.html and feed it real nmap trace lines,
// in the formats of the nmap versions the distributions ship (7.80 to 7.99).
import { readFileSync } from "node:fs";
const html = readFileSync(process.argv[2], "utf8");
const start = html.indexOf("const PK_MAX"), end = html.indexOf("function liveReport");
const api = new Function(html.slice(start, end) + "; return { parsePacketLine, addPacket, unreachFor };")();

// The same scan, as each version prints it.
const COMMON = `SENT (0.0501s) ARP who-has 172.30.0.40 tell 172.30.0.10
RCVD (0.0505s) ARP reply 172.30.0.40 is-at 5A:77:29:B1:A5:31
RCVD (0.2304s) ICMP [172.30.0.40 > 172.30.0.10 Port unreachable (type=3/code=3) ] IP [ttl=64 id=32600 iplen=56 ]
SENT (0.0260s) ICMP [172.30.0.10 > 172.30.0.20 Echo request (type=8/code=0) id=15012 seq=0] IP [ttl=47 id=24869 iplen=28 ]
RCVD (0.0260s) ICMP [172.30.0.20 > 172.30.0.10 Echo reply (type=0/code=0) id=15012 seq=0] IP [ttl=64 id=32609 iplen=28 ]
CONN (0.0190s) TCP localhost > 172.30.0.30:22 => Connected
NSOCK INFO [0.0180s] nsock_iod_new2(): nsock_iod_new (IOD #1)
80/tcp closed http`;
const SETS = {
  "7.94": `SENT (0.1219s) TCP 172.30.0.10:64370 > 172.30.0.40:80 S ttl=45 id=40939 iplen=44  seq=2229103449 win=1024 <mss 1460>
RCVD (0.1219s) TCP 172.30.0.40:80 > 172.30.0.10:64370 RA ttl=64 id=0 iplen=40  seq=0 win=0
SENT (0.2303s) UDP 172.30.0.10:41610 > 172.30.0.40:53 ttl=43 id=18670 iplen=58
SENT (0.2304s) UDP 172.30.0.10:41610 > 172.30.0.40:54 ttl=45 id=54338 iplen=28
RCVD (0.2309s) UDP 172.30.0.40:53 > 172.30.0.10:41610 ttl=64 id=1116 iplen=83
SENT (0.0324s) ICMPv6 (58) fd00:30::10 > ff02::1:ff00:20 (type=135/code=0) hopl=255 flow=0 payloadlen=32
RCVD (0.0324s) neighbor advertisement fd00:30::20 > fd00:30::10 fd00:30::20 is at 92:f8:41:1d:56:bc
SENT (0.1167s) TCP fd00:30::10:36260 > fd00:30::20:80 S hopl=255 flow=0 payloadlen=24 seq=1469574736 win=1024 <mss 1460>
RCVD (0.1166s) TCP fd00:30::20:80 > fd00:30::10:36260 SA hopl=64 flow=b921d payloadlen=24 seq=2874744270 win=64800 <mss 1440>`,
  "7.80": `SENT (0.1219s) TCP 172.30.0.10:64370 > 172.30.0.40:80 S ttl=45 id=40939 iplen=44  seq=2229103449 win=1024 <mss 1460>
RCVD (0.1219s) TCP 172.30.0.40:80 > 172.30.0.10:64370 RA ttl=64 id=0 iplen=40  seq=0 win=0
SENT (0.2303s) UDP 172.30.0.10:41610 > 172.30.0.40:53 ttl=43 id=18670 iplen=58
SENT (0.2304s) UDP 172.30.0.10:41610 > 172.30.0.40:54 ttl=45 id=54338 iplen=28
RCVD (0.2309s) UDP 172.30.0.40:53 > 172.30.0.10:41610 ttl=64 id=1116 iplen=83
SENT (0.0324s) ICMPv6 (58) fd00:30::10 > ff02::1:ff00:20 (type=135/code=0) hopl=255 flow=0 payloadlen=32
RCVD (0.0324s) ICMPv6 (58) fd00:30::20 > fd00:30::10 (type=136/code=0) hopl=255 flow=0 payloadlen=32
SENT (0.1167s) TCP fd00:30::10:36260 > fd00:30::20:80 S hopl=255 flow=0 payloadlen=24 seq=1469574736 win=1024 <mss 1460>
RCVD (0.1166s) TCP fd00:30::20:80 > fd00:30::10:36260 SA hopl=64 flow=b921d payloadlen=24 seq=2874744270 win=64800 <mss 1440>`,
  "7.99": `SENT (0.1219s) TCP [172.30.0.10:64370 > 172.30.0.40:80 S seq=2229103449 <mss 1460,wscale 5>] IP [ttl=50 id=40939 iplen=44 ]
RCVD (0.1219s) TCP [172.30.0.40:80 > 172.30.0.10:64370 RA seq=0 ack=2229103450] IP [ttl=64 id=0 iplen=40 ]
SENT (0.2303s) UDP 172.30.0.10:41610 > 172.30.0.40:53 IP [ttl=43 id=18670 iplen=58 ]
SENT (0.2304s) UDP 172.30.0.10:41610 > 172.30.0.40:54 IP [ttl=45 id=54338 iplen=28 ]
RCVD (0.2309s) UDP 172.30.0.40:53 > 172.30.0.10:41610 IP [ttl=64 id=1116 iplen=83 ]
SENT (0.0324s) ICMPv6 fd00:30::10 > ff02::1:ff00:20 (type=135/code=0) IP [hopl=255 flow=0 payloadlen=32]
RCVD (0.0324s) neighbor advertisement fd00:30::20 > fd00:30::10 packet too short
SENT (0.1167s) TCP [[fd00:30::10]:36260 > [fd00:30::20]:80 S seq=1469574736 <mss 1460,wscale 5>] IP [hopl=255 flow=0 payloadlen=24]
RCVD (0.1166s) TCP [[fd00:30::20]:80 > [fd00:30::10]:36260 SA seq=2874744270 ack=1469574737 <mss 1440>] IP [hopl=64 flow=b921d payloadlen=24]`,
};

let bad = 0;
for (const [ver, set] of Object.entries(SETS)) {
  const S = { pk: { ports: {}, disc: {}, n: 0, dropped: 0, unreach: {}, ns: [], me: "" } };
  let parsed = 0;
  for (const l of (set + "\n" + COMMON).split("\n")) { const pk = api.parsePacketLine(l); if (pk) { parsed++; api.addPacket(S, pk); } }
  const P = S.pk, lab = (k) => (P.ports[k] || []).map((p) => p.label + (p.guess ? "*" : "")).join(" | ");
  const checks = [
    ["15 trace lines parsed, others ignored", parsed === 15],
    ["TCP 80 on .40: SYN then RST/ACK", lab("172.30.0.40|tcp|80") === "SYN | RST/ACK"],
    ["UDP 53: probe and reply", lab("172.30.0.40|udp|53") === "UDP probe | UDP reply"],
    ["ICMP unreachable kept for pairing", (P.unreach["172.30.0.40"] || []).length === 1],
    ["ICMP unreachable paired with closed UDP 54", (() => {
      const h = { ip: "172.30.0.40", ports: [{ port: 53, proto: "udp", state: "open" }, { port: 54, proto: "udp", state: "closed" }] };
      const a = api.unreachFor(S, h, h.ports[1]), b = api.unreachFor(S, h, h.ports[0]);
      return a && a.guess && /unreachable/.test(a.label) && b === null;
    })()],
    ["ARP is discovery for .40", (P.disc["172.30.0.40"] || []).length === 2],
    ["ping is discovery for .20", (P.disc["172.30.0.20"] || []).map((p) => p.label).join(" | ") === "ICMP echo request | ICMP echo reply"],
    ["IPv6 port 80: SYN, SYN/ACK", lab("fd00:30::20|tcp|80") === "SYN | SYN/ACK"],
    ["IPv6 neighbor discovery under the host", (P.disc["fd00:30::20"] || []).length === 2],
    ["CONN line filed under its port", lab("172.30.0.30|tcp|22") === "Connected"],
    ["our address learned", P.me === "fd00:30::10" || P.me === "172.30.0.10"],
  ];
  let failed = 0;
  for (const [n, ok] of checks) { console.log((ok ? "PASS " : "FAIL ") + "[nmap " + ver + "] " + n); if (!ok) failed++; }
  if (failed) console.log(JSON.stringify(P, (k, v) => (k === "raw" ? undefined : v), 1));
  bad += failed;
}
process.exit(bad ? 1 : 0);
