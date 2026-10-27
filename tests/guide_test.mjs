// First-run guide on the Start screen, in its three real situations:
//   node tests/guide_test.mjs <privileged url> <normal user url> <no nmap url>
// See tests/README.md for the containers that provide the last two.
import { spawn } from "node:child_process";
import { rmSync, mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const [PRIV, NORMAL, NONMAP] = [process.argv[2] || "http://127.0.0.1:8732", process.argv[3] || "http://127.0.0.1:8760", process.argv[4] || "http://127.0.0.1:8759"];
const HERE = path.join(os.tmpdir(), "ariadne-guide-test");
rmSync(HERE, { recursive: true, force: true });  // fresh profile: nothing remembered from earlier runs
mkdirSync(HERE, { recursive: true });
const EDGE = process.env.BROWSER || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9337;
const edge = spawn(EDGE, ["--headless=new", "--remote-debugging-port=" + PORT, "--user-data-dir=" + path.join(HERE, "edge"),
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
const ev = async (expr) => (await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result.result.value;
const click = (sel) => ev(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return false; el.click(); return true; })()`);
const text = (sel) => ev(`(document.querySelector(${JSON.stringify(sel)}) || {}).innerText || ""`);
const steps = () => ev(`[...document.querySelectorAll(".guide .step")].map((s) => s.className.replace("step ", "") + ": " + s.innerText.replace(/\\s+/g, " "))`);
async function open(url) { await cdp("Page.navigate", { url }); await sleep(2500); }
async function shot(name) {
  const r = await cdp("Page.captureScreenshot", { format: "png" });
  writeFileSync(path.join(HERE, name + ".png"), Buffer.from(r.result.data, "base64"));
}

let bad = 0;
function check(name, cond, info) { console.log((cond ? "PASS " : "FAIL ") + name + (cond ? "" : "  -> " + JSON.stringify(info))); if (!cond) bad++; }
await cdp("Runtime.enable"); await cdp("Page.enable");

// Nmap missing: step 1 to do, with this distribution's install command; the guide cannot be hidden.
await open(NONMAP);
let s = await steps();
await shot("1-no-nmap");
check("no nmap: guide shown", s.length === 3, s);
check("no nmap: step 1 to do, with the apt command (Ubuntu)", /^todo: .*Install Nmap.*sudo apt install nmap/.test(s[0]), s[0]);
check("no nmap: first scan button disabled", await ev(`!!document.querySelector("#guide-scan[disabled]")`));
check("no nmap: no Hide button", !(await ev(`!!document.getElementById("guide-hide")`)));
await click("#guide-check"); await sleep(2500);
check("no nmap: Check again says nothing changed", /Nothing changed yet/.test(await text(".guide")), await text(".guide"));

// Normal user: steps 1 done, 2 optional with the exact setcap command, 3 runs a first scan.
await open(NORMAL);
s = await steps();
await shot("2-normal-user");
check("normal user: step 1 done", /^done: .*Nmap 7\.\d+ was found/.test(s[0]), s[0]);
check("normal user: step 2 optional, setcap on the real file", /^todo: .*Optional.*sudo setcap \S+ \/tmp\/nmap/i.test(s[1]), s[1]);
check("normal user: step 3 offers the first scan", /nmap -F (--reason )?127\.0\.0\.1/.test(s[2]) && (await ev(`!!document.querySelector("#guide-scan:not([disabled])")`)), s[2]);
await click("#guide-scan");
for (let i = 0; i < 120 && (await ev(`!!document.getElementById("stop")`)); i++) await sleep(500);
await sleep(1000);
check("first scan ran and finished", /1 host up/.test(await text("#s-scan")), (await text(".phase-now")));
await click("#t-start"); await sleep(1500);
s = await steps();
check("normal user: step 3 done after the scan", /^done: .*Run your first scan/.test(s[2]), s[2]);

// Privileged: all done; hide it, it stays hidden after a reload, and comes back on request.
await open(PRIV);
s = await steps();
await shot("3-privileged");
check("privileged: steps 1 and 2 done", /^done/.test(s[0]) && /^done: .*raw packets/.test(s[1]), s);
await click("#guide-hide"); await sleep(300);
check("hide: guide gone, Getting started link shown", !(await ev(`!!document.querySelector(".guide")`)) && (await ev(`!!document.getElementById("guide-show")`)));
await open(PRIV);
check("hide: still hidden after reload", !(await ev(`!!document.querySelector(".guide")`)));
await click("#guide-show"); await sleep(300);
check("Getting started brings it back", await ev(`!!document.querySelector(".guide")`));

check("no JavaScript errors", !problems.length, problems);
console.log(bad ? bad + " failed" : "all passed");
console.log("screenshots: " + HERE);
edge.kill();
process.exit(bad ? 1 : 0);
