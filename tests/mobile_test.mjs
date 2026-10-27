// Phone-width layout: every screen must fit 360 px without sideways scrolling.
// Usage: node tests/mobile_test.mjs [url]   (needs Node 22+ and Edge or Chrome)
// Runs one small scan against the lab so the Scan screen has content.
import { spawn } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const URL_APP = process.argv[2] || "http://127.0.0.1:8732";
const HERE = path.join(os.tmpdir(), "ariadne-mobile-test");
mkdirSync(HERE, { recursive: true });
const EDGE = process.env.BROWSER || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9335;
const edge = spawn(EDGE, ["--headless=new", "--remote-debugging-port=" + PORT, "--user-data-dir=" + path.join(HERE, "edge"),
  "--no-first-run", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let ws, id = 0;
const pending = new Map();
for (let i = 0; i < 50 && !ws; i++) {
  try {
    const pg = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === "page");
    if (pg) ws = new WebSocket(pg.webSocketDebuggerUrl);
  } catch (e) {}
  if (!ws) await sleep(200);
}
await new Promise((r) => ws.addEventListener("open", r));
ws.addEventListener("message", (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } });
const cdp = (method, params = {}) => new Promise((r) => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expr) => (await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result.result.value;
const click = (sel) => ev(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return false; el.click(); return true; })()`);
async function shot(name) {
  const r = await cdp("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
  writeFileSync(path.join(HERE, name + ".png"), Buffer.from(r.result.data, "base64"));
}

// Elements that stick out past the right edge, skipping ones inside a box that scrolls on its own.
const OVERFLOW = `(() => {
  const W = document.documentElement.clientWidth, out = [];
  const scrolls = (el) => { for (let p = el.parentElement; p; p = p.parentElement) { const s = getComputedStyle(p).overflowX; if (s === "auto" || s === "scroll" || s === "hidden") return true; } return false; };
  for (const el of document.querySelectorAll("body *")) {
    const r = el.getBoundingClientRect();
    if (r.width && r.right > W + 1 && !scrolls(el)) out.push((el.id ? "#" + el.id : el.tagName.toLowerCase() + "." + [...el.classList].join(".")) + " right=" + Math.round(r.right));
  }
  return { page: document.documentElement.scrollWidth, W, out: out.slice(0, 8) };
})()`;

let bad = 0;
// Phones, plus a narrow desktop window (mobile: false) like a window snapped to a corner.
for (const [width, mobile] of [[360, true], [412, true], [480, false]]) {
  await cdp("Emulation.setDeviceMetricsOverride", { width, height: 800, deviceScaleFactor: 1, mobile });
  await cdp("Page.navigate", { url: URL_APP });
  await sleep(2500);
  // Without a viewport meta tag a phone lays the page out 980 px wide and shrinks it.
  const W = await ev("document.documentElement.clientWidth");
  if (Math.abs(W - width) > 20) { console.log("FAIL " + width + "px page is laid out " + W + " px wide (viewport meta missing?)"); bad++; }
  const screens = [["start", null], ["build", "#t-build"], ["scripts", "#t-scripts"], ["history", "#t-history"]];
  for (const [name, tab] of screens) {
    if (tab) { await click(tab); await sleep(400); }
    const r = await ev(OVERFLOW);
    const ok = r.page <= r.W + 1 && !r.out.length;
    console.log((ok ? "PASS " : "FAIL ") + width + "px " + name + (ok ? "" : "  page=" + r.page + " -> " + r.out.join(", ")));
    if (!ok) bad++;
    await shot(width + "-" + name);
  }
  // Scan screen with real content: a small scan of the lab.
  await click("#t-build");
  await click("#cmd-editbtn");
  await ev(`document.getElementById("cmd-edit").value = "nmap -sV -p 22,80 172.30.0.20 172.30.0.40"`);
  await click("#cmd-apply");
  await click("#run");
  for (let i = 0; i < 120 && (await ev(`!!document.getElementById("stop")`)); i++) await sleep(500);
  for (const sub of ["results", "packets", "terminal", "timeline"]) {
    await click(`.subtab[data-sub="${sub}"]`); await sleep(300);
    const r = await ev(OVERFLOW);
    const ok = r.page <= r.W + 1 && !r.out.length;
    console.log((ok ? "PASS " : "FAIL ") + width + "px scan/" + sub + (ok ? "" : "  page=" + r.page + " -> " + r.out.join(", ")));
    if (!ok) bad++;
    await shot(width + "-scan-" + sub);
  }
}
console.log(bad ? bad + " screens overflow" : "all screens fit");
console.log("screenshots: " + HERE);
edge.kill();
process.exit(bad ? 1 : 0);
