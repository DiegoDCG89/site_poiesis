#!/usr/bin/env node
/* Servidor do site da Cia de Teatro Poiesis — sem dependências (só Node 18+).
   Serve o site, guarda o conteúdo editado no painel e valida usuário/senha. */
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "uploads");
const CONTENT_FILE = path.join(DATA_DIR, "content.json");
const AUTH_FILE = path.join(DATA_DIR, "auth.json");
const SESSION_MS = 8 * 60 * 60 * 1000;
const MAX_BODY = 60 * 1024 * 1024;
const MAX_IMG = 10 * 1024 * 1024;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ---------- usuário e senha (senha guardada com hash scrypt) ---------- */
const hashPass = (pass, salt) => crypto.scryptSync(String(pass), salt, 64).toString("hex");
if (!fs.existsSync(AUTH_FILE)) {
  const salt = crypto.randomBytes(16).toString("hex");
  const pass = process.env.ADMIN_PASS || "poiesis@2026";
  fs.writeFileSync(AUTH_FILE, JSON.stringify({
    user: process.env.ADMIN_USER || "admin", salt, hash: hashPass(pass, salt),
    mustChange: !process.env.ADMIN_PASS   // senha padrão => obriga trocar no primeiro acesso
  }, null, 2));
}
let auth = JSON.parse(fs.readFileSync(AUTH_FILE, "utf8"));
const saveAuth = () => fs.writeFileSync(AUTH_FILE, JSON.stringify(auth, null, 2));
const sha = (v) => crypto.createHash("sha256").update(String(v)).digest();
const sameUser = (u) => crypto.timingSafeEqual(sha(u), sha(auth.user));
const samePass = (p) => crypto.timingSafeEqual(Buffer.from(hashPass(p, auth.salt), "hex"), Buffer.from(auth.hash, "hex"));

/* ---------- sessões e limite de tentativas ---------- */
const sessions = new Map();
const attempts = new Map();
const clientIp = (req) => (process.env.TRUST_PROXY === "1" && req.headers["x-forwarded-for"])
  ? String(req.headers["x-forwarded-for"]).split(",")[0].trim() : req.socket.remoteAddress;
function blocked(ip) {
  const a = attempts.get(ip);
  if (!a) return false;
  if (Date.now() - a.t > 15 * 60 * 1000) { attempts.delete(ip); return false; }
  return a.n >= 8;
}
function failed(ip) { const a = attempts.get(ip) || { n: 0, t: Date.now() }; a.n++; attempts.set(ip, a); }
function getSession(req) {
  const m = /(?:^|;\s*)poiesis_sid=([a-f0-9]{64})/.exec(req.headers.cookie || "");
  const s = m && sessions.get(m[1]);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(m[1]); return null; }
  return { token: m[1] };
}
const isHttps = (req) => !!req.socket.encrypted || req.headers["x-forwarded-proto"] === "https";
const cookie = (req, v, age) => `poiesis_sid=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${isHttps(req) ? "; Secure" : ""}`;

/* ---------- conteúdo ---------- */
const httpErr = (status, message) => Object.assign(new Error(message), { status });
const MAGIC = {
  jpeg: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  png: (b) => b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  gif: (b) => b.slice(0, 4).toString("latin1") === "GIF8",
  webp: (b) => b.slice(0, 4).toString("latin1") === "RIFF" && b.slice(8, 12).toString("latin1") === "WEBP"
};
const EXT = { jpeg: "jpg", png: "png", webp: "webp", gif: "gif" };

function imgField(v, used) {
  if (typeof v !== "string" || !v) return "";
  if (/^@[a-z0-9]{1,20}$/.test(v)) return v;                    // imagens padrão embutidas no HTML
  let m = /^uploads\/([a-f0-9]{32}\.(?:jpg|png|webp|gif))$/.exec(v);
  if (m) {                                                       // foto já enviada antes
    if (!fs.existsSync(path.join(UPLOAD_DIR, m[1]))) return "";
    used.add(m[1]); return v;
  }
  m = /^data:image\/(jpeg|png|webp|gif);base64,([A-Za-z0-9+/=]+)$/.exec(v);
  if (m) {                                                       // foto nova: grava em /uploads
    const buf = Buffer.from(m[2], "base64");
    if (!buf.length || buf.length > MAX_IMG || !MAGIC[m[1]](buf)) return "";
    const name = crypto.createHash("sha256").update(buf).digest("hex").slice(0, 32) + "." + EXT[m[1]];
    const f = path.join(UPLOAD_DIR, name);
    if (!fs.existsSync(f)) fs.writeFileSync(f, buf);
    used.add(name); return "uploads/" + name;
  }
  return "";
}
function sanitize(c, used) {
  if (!c || typeof c !== "object") throw httpErr(400, "Conteúdo inválido.");
  const s = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
  const id = (v) => (typeof v === "string" && /^[a-z0-9]{1,40}$/i.test(v) ? v : crypto.randomBytes(5).toString("hex"));
  const pecas = (Array.isArray(c.pecas) ? c.pecas : []).slice(0, 60).map((p) => {
    p = p || {};
    const f = Array.isArray(p.fotos) ? p.fotos : [];
    return { id: id(p.id), title: s(p.title, 120), year: s(p.year, 20), verse: s(p.verse, 400),
             capa: imgField(p.capa, used), fotos: [0, 1, 2, 3, 4].map((i) => imgField(f[i], used)) };
  });
  const shows = (Array.isArray(c.shows) ? c.shows : []).slice(0, 20).map((x) => {
    x = x || {};
    return { id: id(x.id), title: s(x.title, 120), desc: s(x.desc, 4000), verse: s(x.verse, 400),
             datas: s(x.datas, 80), horario: s(x.horario, 40), duracao: s(x.duracao, 40) };
  });
  return { pecas, shows };
}
function writeContent(obj) {
  const tmp = CONTENT_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, CONTENT_FILE);
}

/* ---------- http ---------- */
function send(res, status, obj, headers) {
  res.writeHead(status, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, headers));
  res.end(JSON.stringify(obj));
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json/i.test(req.headers["content-type"] || "")) return reject(httpErr(415, "Formato inválido."));
    let size = 0; const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(httpErr(413, "Fotos demais de uma vez. Salve em etapas.")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch (e) { reject(httpErr(400, "JSON inválido.")); } });
    req.on("error", reject);
  });
}
const MIME = { jpg: "image/jpeg", png: "image/png", webp: "image/webp", gif: "image/gif" };

const server = http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, "http://x").pathname;
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "same-origin");

    if (req.method === "GET" && (p === "/" || p === "/index.html")) {
      const html = fs.readFileSync(path.join(ROOT, "index.html"));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      return res.end(html);
    }
    let m = req.method === "GET" && /^\/uploads\/([a-f0-9]{32}\.(jpg|png|webp|gif))$/.exec(p);
    if (m) {
      const f = path.join(UPLOAD_DIR, m[1]);
      if (!fs.existsSync(f)) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { "Content-Type": MIME[m[2]], "Cache-Control": "public, max-age=31536000, immutable" });
      return fs.createReadStream(f).pipe(res);
    }

    if (p === "/api/content" && req.method === "GET") {
      return send(res, 200, fs.existsSync(CONTENT_FILE) ? JSON.parse(fs.readFileSync(CONTENT_FILE, "utf8")) : {});
    }
    if (p === "/api/me" && req.method === "GET") {
      return send(res, 200, getSession(req) ? { logged: true, user: auth.user, mustChange: !!auth.mustChange } : { logged: false });
    }
    if (p === "/api/login" && req.method === "POST") {
      const ip = clientIp(req);
      if (blocked(ip)) return send(res, 429, { error: "Muitas tentativas." });
      const b = await readJson(req);
      const ok = sameUser(b.user || "") & samePass(b.pass || "") ? true : false;
      if (!ok) { failed(ip); return send(res, 401, { error: "Credenciais inválidas." }); }
      attempts.delete(ip);
      const token = crypto.randomBytes(32).toString("hex");
      sessions.set(token, { exp: Date.now() + SESSION_MS });
      return send(res, 200, { ok: true, user: auth.user, mustChange: !!auth.mustChange }, { "Set-Cookie": cookie(req, token, SESSION_MS / 1000) });
    }
    if (p === "/api/logout" && req.method === "POST") {
      const s = getSession(req); if (s) sessions.delete(s.token);
      return send(res, 200, { ok: true }, { "Set-Cookie": cookie(req, "", 0) });
    }
    if (p === "/api/password" && req.method === "POST") {
      const s = getSession(req);
      if (!s) return send(res, 401, { error: "login" });
      const ip = clientIp(req);
      if (blocked(ip)) return send(res, 429, { error: "Muitas tentativas." });
      const b = await readJson(req);
      if (!samePass(b.current || "")) { failed(ip); return send(res, 401, { error: "Senha atual incorreta." }); }
      const user = String(b.user || "").trim(), next = String(b.next || "");
      if (!/^[A-Za-z0-9._@-]{3,40}$/.test(user)) return send(res, 400, { error: "Usuário: 3 a 40 letras, números ou . _ @ -" });
      if (next.length < 8 || next.length > 200) return send(res, 400, { error: "A nova senha precisa ter ao menos 8 caracteres." });
      if (next === b.current) return send(res, 400, { error: "Escolha uma senha diferente da atual." });
      auth.user = user; auth.salt = crypto.randomBytes(16).toString("hex"); auth.hash = hashPass(next, auth.salt); auth.mustChange = false;
      saveAuth();
      for (const t of [...sessions.keys()]) if (t !== s.token) sessions.delete(t);
      return send(res, 200, { ok: true });
    }
    if (p === "/api/content" && req.method === "PUT") {
      if (!getSession(req)) return send(res, 401, { error: "login" });
      if (auth.mustChange) return send(res, 403, { error: "Defina uma nova senha antes de editar." });
      const used = new Set();
      const clean = sanitize(await readJson(req), used);
      writeContent(clean);
      for (const f of fs.readdirSync(UPLOAD_DIR)) if (/^[a-f0-9]{32}\.(jpg|png|webp|gif)$/.test(f) && !used.has(f)) fs.unlinkSync(path.join(UPLOAD_DIR, f));
      return send(res, 200, clean);
    }
    if (p.startsWith("/api/")) return send(res, 404, { error: "Não encontrado." });
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Não encontrado");
  } catch (e) {
    if (!res.headersSent) send(res, e.status || 500, { error: e.status ? e.message : "Erro interno." });
    if (!e.status) console.error(e);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Site no ar: http://localhost:${PORT}`);
  console.log(`Painel:     http://localhost:${PORT}/#admin`);
  if (auth.mustChange) console.log("Primeiro acesso -> usuário: " + auth.user + " | senha: poiesis@2026 (você será obrigado a trocar)");
});
