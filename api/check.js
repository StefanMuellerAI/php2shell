"use strict";
/*
 * POST /api/check  { "url": "www.example.de" }
 *
 * Fetches the start page ONCE with a normal GET (like a browser visit), follows up to
 * 5 redirects and reports what the server volunteers about PHP. No exploit probes,
 * no extra paths. The checked address is neither logged nor stored.
 */
const http = require("node:http");
const https = require("node:https");
const dns = require("node:dns");
const net = require("node:net");
const zlib = require("node:zlib");
const { analyze } = require("./_analyze.js");

const MAX_REDIRECTS = 5;
const HOP_TIMEOUT_MS = 7000;
const TOTAL_TIMEOUT_MS = 16000;
const MAX_BYTES = 400 * 1024;
const UA = "Mozilla/5.0 (compatible; PHP2Shell-Check/1.0; passive version check; +https://stefanai.de)";

class CheckError extends Error {
  constructor(code, message, status = 400) { super(message); this.code = code; this.status = status; }
}

/* ---------- address safety ---------- */
function v4ToInt(ip) { return ip.split(".").reduce((a, b) => (a << 8) + (+b), 0) >>> 0; }
function inV4(ip, cidr) {
  const [base, bits] = cidr.split("/");
  const mask = bits === "0" ? 0 : (~0 << (32 - +bits)) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(base) & mask);
}
const V4_BLOCK = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
  "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
  "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"];
function isBlockedIp(ip) {
  if (net.isIPv4(ip)) return V4_BLOCK.some((c) => inV4(ip, c));
  if (net.isIPv6(ip)) {
    const s = ip.toLowerCase();
    const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isBlockedIp(mapped[1]);
    if (s === "::" || s === "::1") return true;
    if (/^f[cd]/.test(s)) return true;            // fc00::/7 unique local
    if (/^fe[89ab]/.test(s)) return true;         // fe80::/10 link local
    if (/^ff/.test(s)) return true;               // multicast
    if (/^2001:0?db8:/.test(s)) return true;      // documentation
    if (/^64:ff9b:/.test(s)) return true;         // NAT64
    const sixToFour = s.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4}):/);   // 6to4 embeds an IPv4 address
    if (sixToFour) {
      const h = sixToFour[1].padStart(4, "0") + sixToFour[2].padStart(4, "0");
      const v4 = [0, 2, 4, 6].map((i) => parseInt(h.slice(i, i + 2), 16)).join(".");
      if (isBlockedIp(v4)) return true;
    }
    if (/^2001:(0:|:)/.test(s)) return true;      // Teredo
    if (/^::/.test(s)) return true;               // other IPv4-compatible / reserved
    if (/^100::/.test(s)) return true;            // discard
    return false;
  }
  return true;
}
// Used by http(s).request for every connection, so redirects and DNS rebinding are covered too.
function safeLookup(hostname, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  dns.lookup(hostname, { all: true, verbatim: true }, (err, addrs) => {
    if (err) return callback(err);
    if (!addrs.length || addrs.some((a) => isBlockedIp(a.address))) {
      const e = new Error("blocked address"); e.code = "EBLOCKED"; return callback(e);
    }
    let list = addrs;
    if (options && (options.family === 4 || options.family === 6)) {
      const f = addrs.filter((a) => a.family === options.family);
      if (f.length) list = f;
    }
    if (options && options.all) return callback(null, list);
    return callback(null, list[0].address, list[0].family);
  });
}

function validateUrl(u) {
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new CheckError("scheme", "Nur Web-Adressen mit http oder https lassen sich prüfen.");
  if (u.username || u.password) throw new CheckError("auth", "Bitte die Adresse ohne Zugangsdaten eingeben.");
  if (u.port && u.port !== "80" && u.port !== "443") throw new CheckError("port", "Geprüft werden nur Websites auf den Standard-Ports.");
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new CheckError("blocked", "Diese Adresse zeigt in ein internes Netz und wird nicht geprüft.");
    return;
  }
  if (!host.includes(".") || /\.(local|localhost|internal|intranet|lan|home|corp|test|invalid|example)$/.test(host) || host === "localhost") {
    throw new CheckError("host", "Das sieht nicht nach einer öffentlichen Website aus. Beispiel: www.ihre-firma.de");
  }
}

function normalize(input) {
  let s = String(input == null ? "" : input).trim();
  if (!s) throw new CheckError("empty", "Bitte geben Sie die Adresse Ihrer Website ein.");
  if (s.length > 500) throw new CheckError("long", "Die Adresse ist zu lang.");
  let guessed = false;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) { s = "https://" + s; guessed = true; }
  let u;
  try { u = new URL(s); } catch { throw new CheckError("invalid", "Das sieht nicht nach einer Web-Adresse aus. Beispiel: www.ihre-firma.de"); }
  u.hash = "";
  validateUrl(u);
  return { url: u, guessed };
}

/* ---------- one request ---------- */
const MAX_DECODED = 8 * 1024 * 1024;
function decodeBody(buf, encoding, contentType) {
  // maxOutputLength guards against decompression bombs from the checked site
  const enc = String(encoding || "").toLowerCase();
  const lim = { maxOutputLength: MAX_DECODED };
  try {
    if (enc.includes("gzip")) buf = zlib.gunzipSync(buf, { ...lim, finishFlush: zlib.constants.Z_SYNC_FLUSH });
    else if (enc.includes("br")) buf = zlib.brotliDecompressSync(buf, { ...lim, finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH });
    else if (enc.includes("deflate")) {
      try { buf = zlib.inflateSync(buf, { ...lim, finishFlush: zlib.constants.Z_SYNC_FLUSH }); }
      catch { buf = zlib.inflateRawSync(buf, { ...lim, finishFlush: zlib.constants.Z_SYNC_FLUSH }); }
    }
  } catch { /* too large or broken: keep raw bytes */ }
  if (buf.length > MAX_DECODED) buf = buf.subarray(0, MAX_DECODED);
  const cs = (String(contentType || "").match(/charset=([\w-]+)/i) || [])[1] || "utf-8";
  try { return new TextDecoder(cs).decode(buf); } catch { return buf.toString("latin1"); }
}

function fetchOnce(u, deadline, insecure) {
  return new Promise((resolve, reject) => {
    const mod = u.protocol === "https:" ? https : http;
    const remaining = Math.max(500, Math.min(HOP_TIMEOUT_MS, deadline - Date.now()));
    let settled = false;
    const done = (fn, v) => { if (!settled) { settled = true; clearTimeout(timer); fn(v); } };
    const req = mod.request(u, {
      method: "GET",
      agent: false,
      lookup: safeLookup,
      rejectUnauthorized: !insecure,
      headers: {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        "Accept-Language": "de-DE,de;q=0.9,en;q=0.6",
        "Accept-Encoding": "gzip, deflate, br",
      },
    }, (res) => {
      const chunks = [];
      let size = 0;
      const isRedirect = res.statusCode >= 300 && res.statusCode < 400;
      const finish = () => {
        const body = isRedirect ? "" : decodeBody(Buffer.concat(chunks), res.headers["content-encoding"], res.headers["content-type"]);
        done(resolve, { status: res.statusCode || 0, headers: res.headers, body });
      };
      res.on("data", (c) => {
        if (isRedirect) return;
        size += c.length;
        if (size <= MAX_BYTES) chunks.push(c);
        else { res.removeAllListeners("data"); res.destroy(); finish(); }
      });
      res.on("end", finish);
      res.on("close", finish);
      res.on("error", (e) => (chunks.length ? finish() : done(reject, e)));
    });
    const timer = setTimeout(() => { const e = new Error("timeout"); e.code = "ETIMEDOUT"; req.destroy(e); }, remaining);
    req.on("error", (e) => done(reject, e));
    req.end();
  });
}

const TLS_CODES = /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|ERR_SSL|EPROTO|HOSTNAME_MISMATCH|ALTNAME/i;
function isTlsError(e) { return TLS_CODES.test(String(e && (e.code || e.message))); }
function isConnError(e) { return ["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH"].includes(e && e.code) || isTlsError(e); }

async function crawl(start, deadline) {
  let u = start;
  const hops = [];
  let certProblem = false;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    validateUrl(u);
    if (Date.now() > deadline) { const e = new Error("timeout"); e.code = "ETIMEDOUT"; throw e; }
    let r;
    try {
      r = await fetchOnce(u, deadline, false);
    } catch (e) {
      if (isTlsError(e) && u.protocol === "https:") {
        // Reading public headers needs no trust in the certificate; retry this hop only and report it.
        certProblem = true;
        r = await fetchOnce(u, deadline, true);
      } else throw e;
    }
    hops.push({ url: u.href, status: r.status, headers: r.headers, body: r.body });
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      try { u = new URL(Array.isArray(loc) ? loc[0] : loc, u); } catch { break; }
      u.hash = "";
      continue;
    }
    break;
  }
  const result = analyze(hops);
  result.certProblem = certProblem;
  result.tooManyRedirects = hops.length > MAX_REDIRECTS;
  return result;
}

async function check(input) {
  const { url, guessed } = normalize(input);
  const deadline = Date.now() + TOTAL_TIMEOUT_MS;
  try {
    return await crawl(url, deadline);
  } catch (e) {
    if (guessed && url.protocol === "https:" && isConnError(e) && !isTlsError(e) && Date.now() < deadline - 1500) {
      const u2 = new URL(url.href);
      u2.protocol = "http:";
      return await crawl(u2, deadline);
    }
    throw e;
  }
}

function friendlyError(e) {
  if (e instanceof CheckError) return { status: e.status, code: e.code, message: e.message };
  const c = String((e && e.code) || "");
  if (c === "EBLOCKED") return { status: 400, code: "blocked", message: "Diese Adresse zeigt in ein internes Netz und wird nicht geprüft." };
  if (c === "ENOTFOUND" || c === "EAI_AGAIN" || c === "ENODATA") return { status: 422, code: "dns", message: "Diese Adresse ist nicht auffindbar. Bitte die Schreibweise prüfen." };
  if (c === "ECONNREFUSED") return { status: 422, code: "refused", message: "Der Server hat die Verbindung abgelehnt." };
  if (c === "ETIMEDOUT") return { status: 422, code: "timeout", message: "Die Website hat nicht rechtzeitig geantwortet." };
  if (c === "ECONNRESET") return { status: 422, code: "reset", message: "Die Verbindung wurde vom Server abgebrochen." };
  if (isTlsError(e)) return { status: 422, code: "tls", message: "Mit dem HTTPS-Zertifikat der Website stimmt etwas nicht." };
  return { status: 422, code: "fetch", message: "Die Website ließ sich nicht abrufen." };
}

/* ---------- light per-instance rate limit ---------- */
const hits = new Map();
function rateOk(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  if (arr.length >= 30) { hits.set(ip, arr); return false; }
  arr.push(now);
  hits.set(ip, arr);
  if (hits.size > 5000) hits.clear();
  return true;
}

async function readJson(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") { try { return JSON.parse(req.body); } catch { return null; } }
  return await new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 4096) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(data)); } catch { resolve(null); } });
    req.on("error", () => resolve(null));
  });
}

module.exports = async function handler(req, res) {
  const send = (status, obj) => {
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(JSON.stringify(obj));
  };
  if (req.method !== "POST") { res.setHeader("Allow", "POST"); return send(405, { ok: false, code: "method", message: "Bitte per POST aufrufen." }); }
  const ip = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || (req.socket && req.socket.remoteAddress) || "?";
  if (!rateOk(ip)) return send(429, { ok: false, code: "rate", message: "Zu viele Prüfungen in kurzer Zeit. Bitte in ein paar Minuten noch einmal." });
  const body = await readJson(req);
  try {
    const result = await check(body && body.url);
    return send(200, { ok: true, ...result });
  } catch (e) {
    const f = friendlyError(e);
    return send(f.status, { ok: false, code: f.code, message: f.message });
  }
};

module.exports._internal = { normalize, isBlockedIp, check, safeLookup };
