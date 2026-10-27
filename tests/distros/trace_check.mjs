// Read trace lines on stdin and report any SENT/RCVD/CONN line the page's parser
// does not understand, plus a summary of what it found.
// Usage: <lines> | node tests/distros/trace_check.mjs prototype/index.html
import { readFileSync } from "node:fs";
const html = readFileSync(process.argv[2], "utf8");
const src = html.slice(html.indexOf("const PK_MAX"), html.indexOf("function liveReport"));
const { parsePacketLine } = new Function(src + "; return { parsePacketLine };")();
const lines = readFileSync(0, "utf8").split(/\r?\n/).filter((l) => /^(SENT|RCVD|CONN) /.test(l));
const kinds = {}, bad = [];
for (const l of lines) {
  const pk = parsePacketLine(l);
  if (!pk) { bad.push(l); continue; }
  const k = pk.proto + (pk.flags ? ":" + pk.flags : "") + (pk.proto === "icmp" || pk.proto === "nd" || pk.proto === "arp" ? ":" + pk.label.split(" ").slice(0, 3).join(" ") : "");
  kinds[k] = (kinds[k] || 0) + 1;
  // Addresses must be bare IPv4/IPv6 so packets line up with the hosts in the results.
  const addrOk = (s) => /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+)$/i.test(s);
  if (pk.port !== null && (!addrOk(pk.peer) || isNaN(pk.port))) bad.push("BAD FIELDS (" + pk.peer + "): " + l);
  if (pk.me && !addrOk(pk.me)) bad.push("BAD SOURCE (" + pk.me + "): " + l);
  if (pk.flags && !/^[A-Z]+$/.test(pk.flags)) bad.push("BAD FLAGS (" + pk.flags + "): " + l);
  // Lab IPv6 addresses are fd00:30::N; a shorter one means the address was cut.
  for (const s of [pk.me, pk.peer]) if (s && s.includes(":") && !/^(fd00:30::[0-9a-f]+|fe80:.*|ff02:.*)$/i.test(s)) bad.push("CUT ADDRESS (" + s + "): " + l);
  if (pk.proto !== "nd" && pk.dir !== "conn" && pk.port === null && pk.peer && !addrOk(pk.peer)) bad.push("BAD PEER (" + pk.peer + "): " + l);
}
console.log(`${lines.length} lines, ${bad.length} not understood | ` + Object.keys(kinds).sort().join(", "));
bad.slice(0, 8).forEach((l) => console.log("  ? " + l));
