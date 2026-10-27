// Drive the real page (served by the container) in headless Edge over CDP,
// using only what a person can do: click, type, read the screen.
// Usage: node uitest.mjs [url]
import { spawn } from "node:child_process";
// Needs Node 22+ (built-in WebSocket) and Edge or Chrome; set BROWSER to its path if needed.
import { writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const URL_APP = process.argv[2] || "http://127.0.0.1:8732";
// --windows: the app runs on Windows (no lab); only check the Packets fallback there.
const ONLY_WINDOWS = process.argv.includes("--windows");
const HERE = path.join(os.tmpdir(), "ariadne-ui-test");
const SHOTS = path.join(HERE, "shots");
mkdirSync(SHOTS, { recursive: true });
const EDGE = process.env.BROWSER || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9333;
const edge = spawn(EDGE, ["--headless=new", "--remote-debugging-port=" + PORT, "--user-data-dir=" + path.join(HERE, "edge-ui"),
  "--window-size=1366,900", "--no-first-run", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ws, id = 0;
const pending = new Map(), problems = [];
async function connect() {
  for (let i = 0; i < 50 && !ws; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const pg = list.find((t) => t.type === "page");
      if (pg) ws = new WebSocket(pg.webSocketDebuggerUrl);
    } catch (e) {}
    if (!ws) await sleep(200);
  }
  await new Promise((r) => ws.addEventListener("open", r));
  ws.addEventListener("message", (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
    if (d.method === "Runtime.exceptionThrown") problems.push("JS exception: " + (d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text).split("\n")[0]);
    if (d.method === "Runtime.consoleAPICalled" && d.params.type === "error") problems.push("console.error: " + d.params.args.map((a) => a.value || a.description).join(" "));
  });
}
const cdp = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
async function ev(expr) {
  const r = await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.result.exceptionDetails) throw new Error(expr.slice(0, 80) + " -> " + (r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text));
  return r.result.result.value;
}
async function shot(name) {
  const r = await cdp("Page.captureScreenshot", { format: "png" });
  writeFileSync(path.join(SHOTS, name + ".png"), Buffer.from(r.result.data, "base64"));
}
const click = (sel) => ev(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return false; el.click(); return true; })()`);
const text = (sel) => ev(`(document.querySelector(${JSON.stringify(sel)}) || {}).innerText || ""`);

async function setCommand(cmd) {
  await click("#t-build");
  await click("#cmd-editbtn");
  await ev(`document.getElementById("cmd-edit").value = ${JSON.stringify(cmd)}`);
  await click("#cmd-apply");
}
async function shownCommand() {
  await click("#cmd-editbtn");
  const v = await ev(`document.getElementById("cmd-edit").value`);
  await click("#cmd-cancel");
  return v;
}
async function runAndWait(maxSec, stopAfter) {
  if (!(await click("#run"))) return "no Run button";
  return waitDone(maxSec, stopAfter);
}
// Wait until the running scan ends (the Stop button goes away).
async function waitDone(maxSec, stopAfter) {
  const t0 = Date.now();
  await sleep(700);
  while ((Date.now() - t0) / 1000 < maxSec) {
    if (stopAfter && (Date.now() - t0) / 1000 > stopAfter) { await click("#stop"); stopAfter = 0; }
    if (!(await ev(`!!document.getElementById("stop")`))) return "";
    await sleep(500);
  }
  return "timeout";
}
async function readScan() {
  await click('.subtab[data-sub="results"]');
  const results = await text("#s-scan");
  await click('.subtab[data-sub="terminal"]');
  const term = (await text(".term.main")).split("\n");
  await click('.subtab[data-sub="results"]');
  return { results, term, head: await text(".phase-now") };
}

const R = [];
function check(name, cond, info) { R.push([cond ? "PASS" : "FAIL", name, cond ? "" : info || ""]); console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : "  -> " + (info || ""))); }

await connect();
await cdp("Runtime.enable"); await cdp("Page.enable");
await cdp("Page.navigate", { url: URL_APP });
await sleep(2500);
await shot("01-start");

const scen = [
  { n: "full scan of the lab", cmd: "nmap -sV -O --reason 172.30.0.20 172.30.0.30 172.30.0.40", max: 120,
    ok: (s) => /3 hosts up/.test(s.results) && s.term.some((l) => /^Nmap scan report for/.test(l)) && s.term.filter((l) => /^Starting Nmap/.test(l)).length === 1 && /Live scan/i.test(s.results) },
  { n: "-v --packet-trace shows real packets", cmd: "nmap -v --packet-trace -p 80 172.30.0.20", max: 60,
    ok: (s) => s.term.some((l) => /^SENT/.test(l)) && s.term.some((l) => /Discovered open port 80/.test(l)) },
  { n: "ping sweep", cmd: "nmap -sn 172.30.0.0/24", max: 60, ok: (s) => /([4-9]|\d\d) hosts up/.test(s.results) },  // more when the distro test containers are up
  { n: "list scan", cmd: "nmap -sL 172.30.0.16/28", max: 60, ok: (s) => /listed/i.test(s.head) },
  { n: "quoted --data-string", cmd: 'nmap --data-string "authorized test" -p 80 172.30.0.20', max: 60, quoted: true,
    ok: (s) => /1 host up/.test(s.results) && !s.term.some((l) => /Failed to resolve/.test(l)) },
  { n: "idle scan failure is explained", cmd: "nmap -sI 172.30.0.30 -Pn -p 80 172.30.0.40", max: 60,
    ok: (s) => /What this means/.test(s.results) && /zombie/.test(s.results) && /No results/.test(s.results) && !/Looking for hosts/.test(s.results) },
  { n: "typo in a host name is explained", cmd: "nmap -p 80 no-such-host.invalid 172.30.0.20", max: 60,
    ok: (s) => /What this means/.test(s.results) && /no-such-host/.test(s.results) },
  { n: "stop a T0 scan", cmd: "nmap -T0 -p 80 172.30.0.20", max: 30, stop: 4, ok: (s) => /Stopped/.test(s.head) },
  { n: "IPv6 targets", cmd: "nmap -6 -sV -p 22,80 fd00:30::40 fd00:30::20", max: 60, ok: (s) => /2 hosts up/.test(s.results) },
  { n: "UDP + scripts", cmd: "nmap -sU -sV --script=snmp-info -p 53,161 172.30.0.40", max: 120, ok: (s) => /snmp/i.test(s.results) && /1 host up/.test(s.results) },
  { n: "-A aggressive", cmd: "nmap -A -p 21,22,80,6379 172.30.0.20 172.30.0.30 172.30.0.40", max: 180, ok: (s) => /3 hosts up, [4-9] open ports/.test(s.results) },
];
for (const sc of ONLY_WINDOWS ? [] : scen) {
  await setCommand(sc.cmd);
  if (sc.quoted) { const c = await shownCommand(); check("command line keeps the quotes", /--data-string "authorized test"/.test(c), c); }
  const w = await runAndWait(sc.max, sc.stop);
  const s = await readScan();
  check(sc.n, !w && sc.ok(s), (w ? "[" + w + "] " : "") + JSON.stringify({ head: s.head.slice(0, 200), last: s.term.slice(-5) }));
  await shot(String(R.length).padStart(2, "0") + "-" + sc.n.replace(/[^a-z0-9]+/gi, "-"));
}

// Packets tab: example without --packet-trace, then the button reruns with it and shows real packets.
const packets = async (port) => {
  await click('.subtab[data-sub="packets"]');
  if (port) await click(`.pk-pick button[data-port="${port}"]`);
  return text(".packets");
};
if (!ONLY_WINDOWS) {
  await setCommand("nmap -sS -p 22,80,81 172.30.0.40");
  await runAndWait(60);
  let pk = await packets(22);
  check("packets: example without --packet-trace, with the button", /Example/.test(pk) && /Run again with --packet-trace/.test(pk), pk.slice(0, 300));
  await click("#pk-trace");
  const w = await waitDone(60);
  pk = await packets(22);
  const cmdNow = await text(".sh-cmd");
  check("packets: button reruns with --packet-trace", !w && /--packet-trace/.test(cmdNow), cmdNow);
  check("packets: real handshake for open port 22", /real packets/.test(pk) && /SYN\nSYN\/ACK\nRST|SYN[\s\S]*SYN\/ACK[\s\S]*RST/.test(pk) && /SENT \(/.test(pk) && !/Example/.test(pk), pk.slice(0, 500));
  check("packets: discovery section (ARP)", /How Nmap found 172\.30\.0\.40/.test(pk) && /ARP/.test(pk), pk.slice(0, 400));
  check("packets: port first, then discovery", pk.indexOf("Port on") < pk.indexOf("How Nmap found"), pk.slice(0, 200));
  check("packets tab is not labelled Example when real", !/Example/i.test(await text('.subtab[data-sub="packets"]')), await text('.subtab[data-sub="packets"]'));
  pk = await packets(81);
  check("packets: closed port 81 gets RST/ACK", /RST\/ACK/.test(pk) && /rejects the SYN/.test(pk), pk.slice(0, 400));
  await shot("80-packets-real");

  // nmap randomizes the probe order, so try a few runs.
  for (let i = 1; i <= 3; i++) {
    await setCommand("nmap -sU -p 53,54,55 --packet-trace 172.30.0.40");
    await runAndWait(60);
    const p54 = await packets(54), p55 = await packets(55);
    const one = (s) => (s.match(/ICMP port unreachable \*/g) || []).length === 1;
    check("packets: UDP closed ports each get one ICMP unreachable (run " + i + ")", one(p54) && one(p55) && /pairs such errors/.test(p54),
      (p54 + "\n=====\n" + p55).replace(/\n+/g, " / ").slice(0, 700));
  }
  pk = await packets(53);
  check("packets: UDP open port has a reply", /UDP reply/.test(pk), pk.slice(0, 400));
  await shot("81-packets-udp");

  await setCommand("nmap -sT -p 22,23 --packet-trace 172.30.0.40");
  await runAndWait(60);
  pk = await packets(22);
  check("packets: -sT shows connect() results and an example", /connect\(\) to port 22: connected/.test(pk) && /operating system makes each connection/.test(pk) && /On the wire \(example\)/.test(pk), pk.slice(0, 500));
  await shot("82-packets-connect");

  await setCommand("nmap -sn --packet-trace 172.30.0.20");
  await runAndWait(60);
  pk = await packets();
  check("packets: -sn shows how the host was found", /How Nmap found 172\.30\.0\.20/.test(pk) && /ARP/.test(pk), pk.slice(0, 300));

  await setCommand("nmap -6 -p 80 --packet-trace fd00:30::20");
  await runAndWait(60);
  pk = await packets(80);
  check("packets: IPv6 handshake and neighbor discovery", /SYN\/ACK/.test(pk) && /Neighbor/.test(pk), pk.slice(0, 400));
  await shot("83-packets-ipv6");
} else {
  await setCommand("nmap -sT -p 135,445 127.0.0.1");
  await runAndWait(60);
  const pk = await packets(135);
  check("packets (Windows): explains it is an example, no trace button", /On Windows/.test(pk) && !/Run again with --packet-trace/.test(pk), pk.slice(0, 300));
  await shot("84-packets-windows");
  check("no JavaScript errors", problems.length === 0, problems.join(" | "));
  console.log(`\n${R.length} checks, ${R.filter((r) => r[0] !== "PASS").length} failed`);
  ws.close(); edge.kill();
  process.exit(0);
}

// Disabled options: the Builder must flag them before Run, and Remove must clear them.
await setCommand("nmap -oA home -iL hosts.txt -p 80 172.30.0.20");
const bar = await ev(`document.getElementById("tb-target").value`);
check("target bar follows an edited command", bar === "172.30.0.20", bar);
const warn = await ev(`[...document.querySelectorAll(".warn")].map((w) => w.innerText).join(" || ")`);
check("disabled options are flagged in the Builder", /Not yet/i.test(warn) && /Reading targets/.test(warn) && /Saving to files/.test(warn) && /-oA/.test(warn) && /-iL/.test(warn), warn);
await shot("90-disabled-warning");
await click('[data-act="rmOff"]');
const after = await shownCommand();
check("Remove clears them", !/-oA|-iL/.test(after) && /172\.30\.0\.20/.test(after), after);

// History: saved scans listed; compare two.
await click("#t-history");
await sleep(1500);
const rows = await ev(`document.querySelectorAll("#s-history [data-histsel]").length`);
check("history lists the saved scans", rows >= scen.length, "rows " + rows);
// The page re-renders after each tick, so look the boxes up again each time.
for (let i = 0; i < 2; i++) await ev(`document.querySelectorAll("#s-history [data-histsel]")[${i}].click()`);
check("two scans selected", /Compare \(2\/2\)/.test(await text("#hist-compare")), await text("#hist-compare"));
await click("#hist-compare");
await sleep(1500);
const cmp = await text(".panel.diff");
check("compare two saved scans", /Comparison/i.test(cmp) && /→/.test(cmp), cmp.slice(0, 200));
await shot("91-history-compare");
// Open the saved scan that used a quoted value, then edit it: the quotes must survive.
await ev(`[...document.querySelectorAll("#s-history tr")].find((r) => /data-string/.test(r.innerText)).querySelector("[data-openscan]").click()`);
await sleep(1000);
const savedCmd = await text(".sh-cmd");
check("history shows the quoted value", /--data-string "authorized test"/.test(savedCmd), savedCmd);
await click('#s-scan [data-go="build"]');
const reopened = await shownCommand();
check("editing a saved scan keeps the quoted value", /--data-string "authorized test"/.test(reopened), reopened);
check("no JavaScript errors", problems.length === 0, problems.join(" | "));

writeFileSync(path.join(HERE, "uitest-results.json"), JSON.stringify(R, null, 1));
console.log(`\n${R.length} checks, ${R.filter((r) => r[0] !== "PASS").length} failed`);
ws.close(); edge.kill();
process.exit(0);
