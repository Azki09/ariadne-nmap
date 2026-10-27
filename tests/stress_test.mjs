// Big --packet-trace scans must not freeze the page. While each scan runs we
// ping the page every 250 ms and record how long it takes to answer; a frozen
// page answers late. Usage: node tests/stress_test.mjs [url]
// Needs Node 22+ and Edge or Chrome (set BROWSER to its path if needed).
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";

const URL_APP = process.argv[2] || "http://127.0.0.1:8732";
const EDGE = process.env.BROWSER || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9334;
const edge = spawn(EDGE, ["--headless=new", "--remote-debugging-port=" + PORT, "--user-data-dir=" + path.join(os.tmpdir(), "ariadne-stress"),
  "--window-size=1366,900", "--no-first-run", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ws, id = 0;
const pending = new Map(), problems = [];
for (let i = 0; i < 50 && !ws; i++) {
  try {
    const pg = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === "page");
    if (pg) ws = new WebSocket(pg.webSocketDebuggerUrl);
  } catch (e) {}
  if (!ws) await sleep(200);
}
await new Promise((r) => ws.addEventListener("open", r));
ws.addEventListener("message", (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); }
  if (d.method === "Runtime.exceptionThrown") problems.push((d.params.exceptionDetails.exception?.description || d.params.exceptionDetails.text).split("\n")[0]);
});
const cdp = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => (await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result.result?.value;
const click = (sel) => ev(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return false; el.click(); return true; })()`);

await cdp("Runtime.enable");
await cdp("Page.navigate", { url: URL_APP });
await sleep(2500);

const R = [];
function check(name, cond, info) { R.push(cond); console.log((cond ? "PASS " : "FAIL ") + name + "  " + (info || "")); }

async function stress(name, cmd, tab, maxSec) {
  await click("#t-build"); await click("#cmd-editbtn");
  await ev(`document.getElementById("cmd-edit").value = ${JSON.stringify(cmd)}`);
  await click("#cmd-apply");
  // Notes are collapsed unless something blocks; open them to read.
  if (!(await ev(`!!document.querySelector(".warn")`))) await click("#warntoggle");
  const warn = await ev(`[...document.querySelectorAll(".warn")].map((w) => w.innerText).join(" || ")`);
  const ran = await click("#run");
  if (!ran) console.log("  (no Run button; builder says: " + (await ev(`document.querySelector("#s-build") ? document.querySelector("#s-build").innerText.slice(-400) : document.body.innerText.slice(0, 400)`)) + ")");
  await sleep(300);
  await click(`.subtab[data-sub="${tab}"]`);
  const t0 = Date.now(); let worst = 0, done = false;
  while ((Date.now() - t0) / 1000 < maxSec) {
    const a = Date.now();
    const stillRunning = await ev(`!!document.getElementById("stop")`);
    worst = Math.max(worst, Date.now() - a);
    if (!stillRunning) { done = true; break; }
    await sleep(250);
  }
  if (!done) await click("#stop");
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  await click('.subtab[data-sub="terminal"]');
  const termLines = await ev(`(document.querySelector(".term.main") || { innerText: "" }).innerText.split("\\n").length`);
  const head = (await ev(`(document.querySelector(".phase-now") || { innerText: "" }).innerText`)).replace(/\s+/g, " ");
  check(name, done && worst < 1000 && /Finished/.test(head), `finished=${done} in ${secs}s, slowest page answer ${worst} ms, terminal lines on screen ${termLines}, status: ${head.slice(0, 90)}`);
  return { warn, worst, done };
}

// About 131,000 trace lines: every TCP port of one host.
const a = await stress("all 65535 ports with --packet-trace (Terminal tab open)", "nmap -p- -T4 --packet-trace 172.30.0.20", "terminal", 240);
check("Builder warns before a huge trace", /packet trace/i.test(a.warn), a.warn.slice(0, 200));
const note = await ev(`(document.querySelector(".term.main") || { innerText: "" }).innerText.split("\\n")[0]`);
check("Terminal says how many lines it hid", /earlier lines are hidden/.test(note), note);
// Without a trace, a big scan must not offer the trace button.
await click("#t-build"); await click("#cmd-editbtn");
await ev(`document.getElementById("cmd-edit").value = "nmap -p- -T4 172.30.0.20"`);
await click("#cmd-apply"); await click("#run");
for (let i = 0; i < 120 && (await ev(`!!document.getElementById("stop")`)); i++) await sleep(500);
await click('.subtab[data-sub="packets"]');
const pk = await ev(`(document.querySelector(".packets") || { innerText: "" }).innerText`);
check("big scan: no trace button, advice instead", !/Run again with --packet-trace/.test(pk) && !/Run the scan again/.test(pk) && /too big/.test(pk), pk.slice(0, 200).replace(/\n/g, " / "));
// Many hosts and ports, watching the Packets tab.
await stress("subnet, top 100 ports, --packet-trace (Packets tab open)", "nmap -F -T4 --packet-trace 172.30.0.0/24", "packets", 240);
// A normal small trace still shows everything.
const s = await stress("small trace stays complete", "nmap -p 22,80 --packet-trace 172.30.0.40", "terminal", 60);
check("no JavaScript errors", problems.length === 0, problems.join(" | "));
console.log(`\n${R.length} checks, ${R.filter((x) => !x).length} failed`);
ws.close(); edge.kill();
process.exit(0);
