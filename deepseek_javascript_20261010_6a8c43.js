/**
 * IHMSec — IHackMe Platform (Single File Vercel Edition)
 * 
 * File path: api/index.js
 * 
 * Setup:
 *   1. Vercel Postgres add karo → POSTGRES_URL auto milta hai
 *   2. Vercel KV add karo → KV_REST_API_URL + KV_REST_API_TOKEN auto milte hain
 *   3. SESSION_SECRET env var add karo (32+ random chars)
 *   4. Optional: GROQ_API_KEY for AI
 * 
 * Features:
 *   - Register / Login (bcrypt, 12 rounds)
 *   - Sessions (Vercel KV, HttpOnly __Host- cookies)
 *   - CSRF protection (double-submit cookie)
 *   - Rate limiting per IP
 *   - Postgres (parameterized queries)
 *   - Labs: create, list, submit flag (SHA-256 hash + timingSafeEqual)
 *   - AI chat (Groq)
 *   - Virtual terminal (client-side, 100% safe simulation)
 *   - Security headers (CSP, HSTS, nosniff, DENY frame)
 */

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { sql } from '@vercel/postgres';
import { kv } from '@vercel/kv';
import { z } from 'zod';

// ============================================================
// CONFIG
// ============================================================
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('FATAL: SESSION_SECRET missing or < 32 chars');
}
const SECRET = SESSION_SECRET || 'insecure-fallback-do-not-use';
const SESSION_COOKIE = '__Host-ihm.sid';
const CSRF_COOKIE = '__Host-ihm.csrf';
const SESSION_TTL = 7200; // seconds

// ============================================================
// SECURITY HELPERS
// ============================================================
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

const timingSafeEqualHex = (a, b) => {
  try {
    const A = Buffer.from(a, 'hex');
    const B = Buffer.from(b, 'hex');
    if (A.length !== B.length) return false;
    return crypto.timingSafeEqual(A, B);
  } catch { return false; }
};

const json = (res, status, body) => {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
};

const parseBody = (req) => new Promise((resolve) => {
  let data = '';
  req.on('data', (c) => {
    data += c;
    if (data.length > 64 * 1024) { req.destroy(); resolve({}); }
  });
  req.on('end', () => {
    try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); }
  });
  req.on('error', () => resolve({}));
});

const parseCookies = (req) => {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > -1) {
      const k = p.slice(0, i).trim();
      const v = p.slice(i + 1).trim();
      try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
    }
  });
  return out;
};

const setCookie = (res, name, value, maxAge) => {
  const secure = ' Secure;';
  res.setHeader('Set-Cookie',
    `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict;${secure} Max-Age=${maxAge}`);
};

const clientIp = (req) => {
  const xff = req.headers['x-forwarded-for'];
  return (xff ? xff.split(',')[0].trim() : req.socket?.remoteAddress) || 'unknown';
};

// In-memory rate limiter (per lambda instance)
const buckets = new Map();
const rateLimit = (key, max, windowMs) => {
  const now = Date.now();
  const b = buckets.get(key) || { count: 0, reset: now + windowMs };
  if (now > b.reset) { b.count = 0; b.reset = now + windowMs; }
  b.count++;
  buckets.set(key, b);
  return b.count <= max;
};

// ============================================================
// DATABASE SCHEMA
// ============================================================
let schemaReady = false;
const ensureSchema = async () => {
  if (schemaReady) return;
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(16) NOT NULL DEFAULT 'user',
      points INTEGER NOT NULL DEFAULT 0,
      failed_logins INTEGER NOT NULL DEFAULT 0,
      locked_until BIGINT NOT NULL DEFAULT 0,
      created_at BIGINT NOT NULL
    )
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS labs (
      id SERIAL PRIMARY KEY,
      slug VARCHAR(40) UNIQUE NOT NULL,
      title VARCHAR(80) NOT NULL,
      description TEXT NOT NULL,
      difficulty VARCHAR(16) NOT NULL DEFAULT 'easy',
      category VARCHAR(30) NOT NULL DEFAULT 'general',
      author_id INTEGER NOT NULL,
      flag_hash TEXT NOT NULL,
      points INTEGER NOT NULL DEFAULT 10,
      is_public BOOLEAN NOT NULL DEFAULT TRUE,
      created_at BIGINT NOT NULL
    )
  `;
  await sql`
    CREATE TABLE IF NOT EXISTS solves (
      user_id INTEGER NOT NULL,
      lab_id INTEGER NOT NULL,
      solved_at BIGINT NOT NULL,
      PRIMARY KEY (user_id, lab_id)
    )
  `;
  schemaReady = true;
};

// ============================================================
// SESSION (Vercel KV)
// ============================================================
const createSession = async (userId) => {
  const sid = crypto.randomBytes(32).toString('hex');
  await kv.set(`sess:${sid}`, { userId, created: Date.now() }, { ex: SESSION_TTL });
  return sid;
};

const getSession = async (sid) => {
  if (!sid || !/^[a-f0-9]{64}$/.test(sid)) return null;
  try { return await kv.get(`sess:${sid}`); } catch { return null; }
};

const destroySession = async (sid) => {
  if (sid) { try { await kv.del(`sess:${sid}`); } catch {} }
};

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
const requireAuth = async (req, res) => {
  const cookies = parseCookies(req);
  const sess = await getSession(cookies[SESSION_COOKIE]);
  if (!sess) { json(res, 401, { error: 'Unauthorized' }); return null; }
  const { rows } = await sql`
    SELECT id, username, role, points, locked_until FROM users WHERE id = ${sess.userId}
  `;
  const u = rows[0];
  if (!u || Number(u.locked_until) > Date.now()) {
    json(res, 401, { error: 'Session invalid' }); return null;
  }
  return u;
};

const requireCsrf = (req, res) => {
  const cookies = parseCookies(req);
  const cookieToken = cookies[CSRF_COOKIE];
  const headerToken = req.headers['x-csrf-token'];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    json(res, 403, { error: 'CSRF invalid' }); return false;
  }
  return true;
};

// ============================================================
// VALIDATION
// ============================================================
const RegisterSchema = z.object({
  username: z.string().min(3).max(24).regex(/^[a-zA-Z0-9_]+$/),
  password: z.string().min(10).max(200)
});
const LoginSchema = z.object({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(200)
});
const LabSchema = z.object({
  slug: z.string().min(3).max(40).regex(/^[a-z0-9-]+$/),
  title: z.string().min(3).max(80),
  description: z.string().min(10).max(2000),
  difficulty: z.enum(['easy', 'medium', 'hard', 'insane']),
  category: z.string().min(2).max(30).regex(/^[a-zA-Z0-9 _-]+$/),
  flag: z.string().min(6).max(200).regex(/^IHM\{[\x20-\x7E]+\}$/),
  points: z.number().int().min(5).max(500),
  is_public: z.boolean().default(true)
});
const SubmitSchema = z.object({
  labId: z.number().int().positive(),
  flag: z.string().min(1).max(300)
});

// ============================================================
// FRONTEND HTML (inlined)
// ============================================================
const FRONTEND_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>IHMSec — IHackMe</title>
<style>
:root{--bg:#0a0e14;--panel:#111721;--border:#1f2937;--fg:#e6edf3;--mut:#8b949e;--grn:#3fb950;--blu:#58a6ff;--red:#f85149;--pur:#d2a8ff}
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI',system-ui,sans-serif}
body{background:var(--bg);color:var(--fg);min-height:100vh;padding:16px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:14px}
h1,h2,h3{margin-bottom:10px}
input,textarea,select{width:100%;background:#0a0e14;border:1px solid var(--border);color:var(--fg);padding:10px;border-radius:6px;margin-bottom:8px;font-family:inherit}
textarea{min-height:80px;font-family:Consolas,monospace}
button{background:var(--grn);color:#fff;border:0;padding:10px 16px;border-radius:6px;cursor:pointer;font-weight:600}
button:hover{filter:brightness(1.15)}
button.ghost{background:transparent;border:1px solid var(--border);color:var(--fg)}
.row{display:flex;gap:8px;flex-wrap:wrap}
.mut{color:var(--mut);font-size:13px}
.hidden{display:none!important}
#auth{max-width:360px;margin:60px auto}
header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:var(--panel);border:1px solid var(--border);border-radius:10px;margin-bottom:14px;flex-wrap:wrap;gap:8px}
main{display:grid;grid-template-columns:1fr 1fr;gap:14px;max-width:1200px;margin:0 auto}
main .card:nth-child(3){grid-column:1/-1}
#term,#chat{background:#050810;border:1px solid var(--border);border-radius:6px;padding:10px;height:240px;overflow-y:auto;font-family:Consolas,monospace;font-size:13px;white-space:pre-wrap;margin-bottom:6px}
.term-input{display:flex;align-items:center;gap:8px;background:#050810;border:1px solid var(--border);border-radius:6px;padding:6px 10px}
.term-input input{border:0;background:transparent;margin:0;padding:4px}
.term-input span{color:var(--grn);font-weight:bold}
.lvl{border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:8px;display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap}
.lvl.solved{border-color:var(--grn);background:#0d1f12}
.lvl-info{flex:1;min-width:200px}
.lvl-info h3{font-size:14px}
.lvl-info .meta{font-size:11px;color:var(--mut);margin-bottom:4px}
.lvl-info p{font-size:12px;color:var(--mut);white-space:pre-wrap}
.lvl input{width:170px;margin:0;font-size:12px;padding:6px}
.lvl button{padding:6px 10px;font-size:12px}
.u{color:var(--blu)}.a{color:var(--pur)}.e{color:var(--red)}.g{color:var(--grn)}
@media(max-width:800px){main{grid-template-columns:1fr}}
</style>
</head>
<body>

<div id="auth" class="card">
  <h1>🔐 IHMSec</h1>
  <p class="mut">IHackMe — Free Ethical Hacking Labs</p>
  <input id="u" placeholder="username" autocomplete="username" />
  <input id="p" type="password" placeholder="password (10+ chars)" autocomplete="current-password" />
  <div class="row" style="margin-top:8px">
    <button id="loginBtn">Login</button>
    <button id="regBtn" class="ghost">Register</button>
  </div>
  <p id="aMsg" class="mut" style="margin-top:10px;color:var(--red)"></p>
</div>

<div id="app" class="hidden">
  <header>
    <div>👤 <span id="who" class="u"></span> | ⭐ <span id="pts">0</span> pts | <span id="role" class="mut"></span></div>
    <div class="row">
      <button id="createLabBtn" class="ghost">+ Create Lab</button>
      <button id="logoutBtn" class="ghost">Logout</button>
    </div>
  </header>

  <main>
    <section class="card">
      <h2>🎯 Labs</h2>
      <div id="labs"></div>
    </section>

    <section class="card">
      <h2>💻 Virtual Terminal <span class="mut" style="font-size:11px">(safe simulation)</span></h2>
      <div id="term"></div>
      <div class="term-input">
        <span>$</span>
        <input id="cmd" placeholder="type 'help'" autocomplete="off" />
      </div>
    </section>

    <section class="card">
      <h2>🤖 IHMBot</h2>
      <div id="chat"></div>
      <div class="term-input">
        <span>&gt;</span>
        <input id="aiIn" placeholder="Ask about hacking..." autocomplete="off" />
      </div>
    </section>
  </main>
</div>

<div id="labModal" class="hidden" style="position:fixed;inset:0;background:rgba(0,0,0,.75);display:flex;align-items:center;justify-content:center;padding:20px;z-index:999">
  <div class="card" style="max-width:600px;width:100%;max-height:90vh;overflow-y:auto">
    <h2>🧪 Create Lab</h2>
    <input id="lSlug" placeholder="slug (e.g. web-recon-01)" />
    <input id="lTitle" placeholder="Title" />
    <textarea id="lDesc" placeholder="Description / hints"></textarea>
    <div class="row">
      <select id="lDiff" style="flex:1">
        <option value="easy">Easy</option>
        <option value="medium">Medium</option>
        <option value="hard">Hard</option>
        <option value="insane">Insane</option>
      </select>
      <input id="lCat" placeholder="category" value="general" style="flex:1" />
      <input id="lPts" type="number" min="5" max="500" value="10" style="flex:0 0 90px" />
    </div>
    <input id="lFlag" placeholder="IHM{your_flag_here}" />
    <label class="mut" style="display:flex;gap:6px;align-items:center;margin:6px 0">
      <input type="checkbox" id="lPub" checked style="width:auto;margin:0" /> Public
    </label>
    <div class="row">
      <button id="saveLab">Save Lab</button>
      <button id="closeLab" class="ghost">Cancel</button>
    </div>
    <p id="labMsg" class="mut" style="margin-top:8px"></p>
  </div>
</div>

<script>
'use strict';
const $ = (id) => document.getElementById(id);
let CSRF = '';
const STORE_KEY = 'ihm_vfs_v1';

async function getCsrf() {
  const r = await fetch('/api/csrf', { credentials: 'same-origin' });
  const j = await r.json();
  CSRF = j.token;
}

async function api(url, body) {
  const opts = { method: body ? 'POST' : 'GET', credentials: 'same-origin', headers: {} };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['x-csrf-token'] = CSRF;
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(url, opts);
  if (r.status === 403) { await getCsrf(); return { error: 'CSRF retry, please try again' }; }
  try { return await r.json(); } catch { return { error: 'Bad response' }; }
}

function log(el, text, cls) {
  const d = document.createElement('div');
  if (cls) d.className = cls;
  d.textContent = text;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}

// ---------- Virtual Filesystem ----------
function defaultFS() {
  return {
    cwd: '/home/hacker',
    files: {
      '/home/hacker/README.txt': 'Welcome to IHMSec!\\nTry: ls, cat README.txt, ls -la, find / -name "*flag*"\\n',
      '/home/hacker/notes.txt': 'Hidden files start with a dot.\\nRun: ls -la\\n',
      '/home/hacker/.secret/answer.txt': 'IHM{demo_h1dd3n_f1l3}\\n',
      '/etc/hostname': 'ihmsec-sandbox\\n',
      '/etc/os-release': 'NAME="IHMSec Sandbox"\\nVERSION="1.0"\\n'
    }
  };
}
function loadFS() {
  try { return JSON.parse(localStorage.getItem(STORE_KEY)) || defaultFS(); }
  catch { return defaultFS(); }
}
function saveFS(fs) { localStorage.setItem(STORE_KEY, JSON.stringify(fs)); }

function resolvePath(fs, p) {
  if (!p) return fs.cwd;
  let path = p.startsWith('/') ? p : (fs.cwd === '/' ? '/' + p : fs.cwd + '/' + p);
  const parts = path.split('/').filter(Boolean);
  const stack = [];
  for (const s of parts) {
    if (s === '.') continue;
    if (s === '..') stack.pop(); else stack.push(s);
  }
  return '/' + stack.join('/');
}

function vfsLs(fs, target, all) {
  const base = target ? resolvePath(fs, target) : fs.cwd;
  const entries = new Map();
  for (const f of Object.keys(fs.files)) {
    if (!f.startsWith(base === '/' ? '/' : base + '/')) continue;
    const rest = f.slice(base === '/' ? 1 : base.length + 1);
    if (!rest) continue;
    const top = rest.split('/')[0];
    if (!all && top.startsWith('.')) continue;
    const isDir = rest.includes('/');
    entries.set(top, isDir);
  }
  if (entries.size === 0) return '';
  return [...entries.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([n, d]) => (d ? n + '/' : n)).join('  ') + '\\n';
}

function vfsExec(fs, cmd) {
  const tokens = cmd.trim().split(/\\s+/);
  const bin = tokens[0];
  const args = tokens.slice(1);
  const flags = args.filter(a => a.startsWith('-'));
  const rest = args.filter(a => !a.startsWith('-'));

  switch (bin) {
    case 'help':
      return 'Commands: ls, cat, pwd, cd, whoami, id, echo, find, head, tree, clear, help\\n';
    case 'pwd': return fs.cwd + '\\n';
    case 'whoami': return 'hacker\\n';
    case 'id': return 'uid=1000(hacker) gid=1000(hacker) groups=1000(hacker)\\n';
    case 'echo': return rest.join(' ') + '\\n';
    case 'ls': {
      const all = flags.some(f => f.includes('a'));
      const long = flags.some(f => f.includes('l'));
      const out = vfsLs(fs, rest[0], all);
      if (long) {
        return out.split(/\\s+/).filter(Boolean).map(n => '-rw-r--r-- 1 hacker hacker 0 Jan 1 00:00 ' + n).join('\\n') + (out ? '\\n' : '');
      }
      return out;
    }
    case 'cd': {
      const target = rest[0] || '/home/hacker';
      const p = resolvePath(fs, target);
      // Check if dir exists (any file under it)
      const has = Object.keys(fs.files).some(f => f.startsWith(p + '/') || f === p);
      if (!has) return 'cd: no such directory: ' + target + '\\n';
      fs.cwd = p;
      saveFS(fs);
      return '';
    }
    case 'cat': {
      if (!rest[0]) return 'cat: missing file\\n';
      const p = resolvePath(fs, rest[0]);
      return fs.files[p] !== undefined ? fs.files[p] : 'cat: ' + rest[0] + ': No such file\\n';
    }
    case 'head': {
      if (!rest[0]) return 'head: missing file\\n';
      const p = resolvePath(fs, rest[0]);
      if (fs.files[p] === undefined) return 'head: no such file\\n';
      return fs.files[p].split('\\n').slice(0, 10).join('\\n') + '\\n';
    }
    case 'find': {
      const pattern = rest[rest.length - 1] || '';
      const pat = pattern.replace(/^["']|["']$/g, '');
      return Object.keys(fs.files)
        .filter(f => !pat || f.includes(pat.replace(/\\*/g, '')))
        .join('\\n') + '\\n';
    }
    case 'tree': {
      return Object.keys(fs.files).sort().join('\\n') + '\\n';
    }
    case 'clear':
      return '__CLEAR__';
    default:
      return bin + ': command not found (try: help)\\n';
  }
}

// ---------- Boot ----------
async function boot() {
  await getCsrf();
  const me = await api('/api/me');
  if (me.username) enterApp(me);
}

$('loginBtn').onclick = async () => {
  $('aMsg').textContent = '';
  const r = await api('/api/login', { username: $('u').value, password: $('p').value });
  if (r.ok) enterApp(r); else $('aMsg').textContent = r.error || 'Failed';
};
$('regBtn').onclick = async () => {
  $('aMsg').textContent = '';
  const r = await api('/api/register', { username: $('u').value, password: $('p').value });
  if (r.ok) enterApp(r); else $('aMsg').textContent = r.error || 'Failed';
};
$('logoutBtn').onclick = async () => { await api('/api/logout', {}); location.reload(); };

function enterApp(u) {
  $('auth').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('who').textContent = u.username;
  $('pts').textContent = u.points || 0;
  $('role').textContent = u.role || 'user';
  loadLabs();
  log($('term'), 'Welcome ' + u.username + '. Type `help` to see commands.', 'u');
}

async function loadLabs() {
  const labs = await api('/api/labs');
  const me = await api('/api/me');
  const solved = new Set(me.solved || []);
  const box = $('labs');
  box.textContent = '';
  if (!Array.isArray(labs) || labs.length === 0) {
    const p = document.createElement('p');
    p.className = 'mut';
    p.textContent = 'Abhi koi lab nahi hai. "+ Create Lab" se pehla lab banao.';
    box.appendChild(p);
    return;
  }
  labs.forEach(l => {
    const s = solved.has(l.id);
    const div = document.createElement('div');
    div.className = 'lvl' + (s ? ' solved' : '');
    const info = document.createElement('div');
    info.className = 'lvl-info';
    const h3 = document.createElement('h3');
    h3.textContent = (s ? '✅ ' : '🔒 ') + l.title;
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = l.difficulty + ' • ' + l.category + ' • ' + l.points + ' pts • by ' + l.author;
    const p = document.createElement('p');
    p.textContent = l.description;
    info.append(h3, meta, p);

    const input = document.createElement('input');
    input.placeholder = 'IHM{...}';
    input.disabled = s;

    const btn = document.createElement('button');
    btn.textContent = 'Submit';
    btn.disabled = s;
    btn.onclick = async () => {
      const r = await api('/api/submit', { labId: l.id, flag: input.value });
      if (r.ok) { $('pts').textContent = r.points; loadLabs(); }
      else alert(r.message || r.error);
    };
    div.append(info, input, btn);
    box.appendChild(div);
  });
}

$('cmd').addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const cmd = e.target.value.trim();
  if (!cmd) return;
  e.target.value = '';
  log($('term'), '$ ' + cmd, 'u');
  const fs = loadFS();
  const out = vfsExec(fs, cmd);
  if (out === '__CLEAR__') { $('term').textContent = ''; return; }
  if (out) log($('term'), out);
});

$('aiIn').addEventListener('keydown', async (e) => {
  if (e.key !== 'Enter') return;
  const msg = e.target.value.trim();
  if (!msg) return;
  e.target.value = '';
  log($('chat'), 'You: ' + msg, 'u');
  const r = await api('/api/ai', { message: msg });
  log($('chat'), 'IHMBot: ' + (r.reply || r.error), 'a');
});

$('createLabBtn').onclick = () => { $('labModal').classList.remove('hidden'); $('labMsg').textContent = ''; };
$('closeLab').onclick = () => $('labModal').classList.add('hidden');
$('saveLab').onclick = async () => {
  const body = {
    slug: $('lSlug').value.trim(),
    title: $('lTitle').value.trim(),
    description: $('lDesc').value.trim(),
    difficulty: $('lDiff').value,
    category: $('lCat').value.trim() || 'general',
    points: parseInt($('lPts').value, 10) || 10,
    flag: $('lFlag').value.trim(),
    is_public: $('lPub').checked
  };
  const r = await api('/api/labs', body);
  if (r.ok) {
    $('labMsg').style.color = 'var(--grn)';
    $('labMsg').textContent = 'Lab created!';
    loadLabs();
    setTimeout(() => $('labModal').classList.add('hidden'), 700);
  } else {
    $('labMsg').style.color = 'var(--red)';
    $('labMsg').textContent = r.error || 'Failed';
  }
};

boot();
</script>
</body>
</html>`;

// ============================================================
// MAIN HANDLER
// ============================================================
export default async function handler(req, res) {
  // ---- Global security headers ----
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
  if (process.env.VERCEL) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  // ---- Route parsing ----
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  try {
    // Frontend
    if (path === '/' || path === '/index.html') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.statusCode = 200;
      return res.end(FRONTEND_HTML);
    }

    // CSRF
    if (path === '/api/csrf' && req.method === 'GET') {
      const cookies = parseCookies(req);
      let token = cookies[CSRF_COOKIE];
      if (!token || !/^[a-f0-9]{64}$/.test(token)) {
        token = crypto.randomBytes(32).toString('hex');
        setCookie(res, CSRF_COOKIE, token, 7200);
      }
      return json(res, 200, { token });
    }

    // Ensure DB is ready for all other API calls
    if (path.startsWith('/api/')) await ensureSchema();

    // ---- REGISTER ----
    if (path === '/api/register' && req.method === 'POST') {
      if (!rateLimit(`reg:${clientIp(req)}`, 5, 15 * 60 * 1000))
        return json(res, 429, { error: 'Too many attempts' });
      if (!requireCsrf(req, res)) return;
      const parsed = RegisterSchema.safeParse(await parseBody(req));
      if (!parsed.success) return json(res, 400, { error: 'Invalid input' });
      const { username, password } = parsed.data;

      const exists = await sql`SELECT id FROM users WHERE LOWER(username) = LOWER(${username})`;
      if (exists.rows.length) return json(res, 409, { error: 'Username taken' });

      const hash = await bcrypt.hash(password, 12);
      const { rows } = await sql`
        INSERT INTO users (username, password_hash, role, created_at)
        VALUES (${username}, ${hash}, 'user', ${Date.now()})
        RETURNING id, username, role
      `;
      const u = rows[0];
      const sid = await createSession(u.id);
      setCookie(res, SESSION_COOKIE, sid, SESSION_TTL);
      return json(res, 200, { ok: true, username: u.username, points: 0, role: u.role, solved: [] });
    }

    // ---- LOGIN ----
    if (path === '/api/login' && req.method === 'POST') {
      if (!rateLimit(`login:${clientIp(req)}`, 10, 15 * 60 * 1000))
        return json(res, 429, { error: 'Too many attempts' });
      if (!requireCsrf(req, res)) return;
      const parsed = LoginSchema.safeParse(await parseBody(req));
      if (!parsed.success) return json(res, 400, { error: 'Invalid input' });
      const { username, password } = parsed.data;

      const { rows } = await sql`SELECT * FROM users WHERE LOWER(username) = LOWER(${username})`;
      const u = rows[0];
      const dummy = '$2a$12$' + 'x'.repeat(53);
      const ok = await bcrypt.compare(password, u ? u.password_hash : dummy);

      if (!u || !ok) {
        if (u) {
          const fails = u.failed_logins + 1;
          const lock = fails >= 5 ? Date.now() + 15 * 60 * 1000 : 0;
          await sql`UPDATE users SET failed_logins = ${fails}, locked_until = ${lock} WHERE id = ${u.id}`;
        }
        return json(res, 401, { error: 'Invalid credentials' });
      }
      if (Number(u.locked_until) > Date.now())
        return json(res, 423, { error: 'Account locked' });

      await sql`UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ${u.id}`;
      const sid = await createSession(u.id);
      setCookie(res, SESSION_COOKIE, sid, SESSION_TTL);

      const solved = await sql`SELECT lab_id FROM solves WHERE user_id = ${u.id}`;
      return json(res, 200, {
        ok: true, username: u.username, role: u.role, points: u.points,
        solved: solved.rows.map(r => r.lab_id)
      });
    }

    // ---- LOGOUT ----
    if (path === '/api/logout' && req.method === 'POST') {
      if (!requireCsrf(req, res)) return;
      const cookies = parseCookies(req);
      await destroySession(cookies[SESSION_COOKIE]);
      res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0`);
      return json(res, 200, { ok: true });
    }

    // ---- ME ----
    if (path === '/api/me' && req.method === 'GET') {
      const u = await requireAuth(req, res);
      if (!u) return;
      const solved = await sql`SELECT lab_id FROM solves WHERE user_id = ${u.id}`;
      return json(res, 200, {
        id: u.id, username: u.username, role: u.role, points: u.points,
        solved: solved.rows.map(r => r.lab_id)
      });
    }

    // ---- LABS ----
    if (path === '/api/labs' && req.method === 'GET') {
      const { rows } = await sql`
        SELECT l.id, l.slug, l.title, l.description, l.difficulty, l.category,
               l.points, l.is_public, u.username AS author
        FROM labs l JOIN users u ON u.id = l.author_id
        WHERE l.is_public = TRUE
        ORDER BY l.created_at DESC LIMIT 200
      `;
      return json(res, 200, rows);
    }
    if (path === '/api/labs' && req.method === 'POST') {
      if (!rateLimit(`lab:${clientIp(req)}`, 5, 60 * 1000))
        return json(res, 429, { error: 'Slow down' });
      if (!requireCsrf(req, res)) return;
      const u = await requireAuth(req, res);
      if (!u) return;
      const parsed = LabSchema.safeParse(await parseBody(req));
      if (!parsed.success)
        return json(res, 400, { error: 'Invalid: ' + parsed.error.issues.map(i => i.path.join('.') + ' ' + i.message).join(', ') });
      const d = parsed.data;
      const exists = await sql`SELECT id FROM labs WHERE slug = ${d.slug}`;
      if (exists.rows.length) return json(res, 409, { error: 'Slug taken' });
      const flagHash = sha256(d.flag);
      const { rows } = await sql`
        INSERT INTO labs (slug, title, description, difficulty, category,
                          author_id, flag_hash, points, is_public, created_at)
        VALUES (${d.slug}, ${d.title}, ${d.description}, ${d.difficulty}, ${d.category},
                ${u.id}, ${flagHash}, ${d.points}, ${d.is_public}, ${Date.now()})
        RETURNING id, slug
      `;
      return json(res, 200, { ok: true, id: rows[0].id, slug: rows[0].slug });
    }

    // ---- SUBMIT FLAG ----
    if (path === '/api/submit' && req.method === 'POST') {
      if (!rateLimit(`sub:${clientIp(req)}`, 20, 60 * 1000))
        return json(res, 429, { error: 'Slow down' });
      if (!requireCsrf(req, res)) return;
      const u = await requireAuth(req, res);
      if (!u) return;
      const parsed = SubmitSchema.safeParse(await parseBody(req));
      if (!parsed.success) return json(res, 400, { error: 'Invalid input' });
      const { labId, flag } = parsed.data;

      const lab = await sql`SELECT id, flag_hash, points FROM labs WHERE id = ${labId}`;
      if (!lab.rows.length) return json(res, 404, { error: 'Lab not found' });

      const already = await sql`SELECT 1 FROM solves WHERE user_id = ${u.id} AND lab_id = ${labId}`;
      if (already.rows.length) return json(res, 200, { ok: false, message: 'Already solved' });

      const submitted = sha256(flag.trim());
      if (!timingSafeEqualHex(lab.rows[0].flag_hash, submitted))
        return json(res, 200, { ok: false, message: 'Wrong flag' });

      await sql`INSERT INTO solves (user_id, lab_id, solved_at)
                VALUES (${u.id}, ${labId}, ${Date.now()})
                ON CONFLICT DO NOTHING`;
      const { rows } = await sql`
        UPDATE users SET points = points + ${lab.rows[0].points}
        WHERE id = ${u.id} RETURNING points
      `;
      return json(res, 200, { ok: true, message: 'Correct! 🎉', points: rows[0].points });
    }

    // ---- AI ----
    if (path === '/api/ai' && req.method === 'POST') {
      if (!rateLimit(`ai:${clientIp(req)}`, 15, 60 * 1000))
        return json(res, 429, { error: 'AI rate limit' });
      if (!requireCsrf(req, res)) return;
      const u = await requireAuth(req, res);
      if (!u) return;
      const body = await parseBody(req);
      const msg = (body.message || '').toString().slice(0, 1000);
      if (!msg) return json(res, 400, { error: 'Empty message' });

      const key = process.env.GROQ_API_KEY;
      if (!key) return json(res, 200, { reply: 'AI offline. Add GROQ_API_KEY in Vercel env vars.' });

      try {
        const r = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: 'llama-3.1-8b-instant',
            messages: [
              { role: 'system', content: 'You are IHMBot, mentor for IHMSec ethical hacking labs. Reply short (2-4 lines). Help with recon, privilege escalation, web, crypto concepts. Never produce real-world exploits.' },
              { role: 'user', content: msg }
            ],
            temperature: 0.6,
            max_tokens: 300
          })
        });
        const data = await r.json();
        return json(res, 200, { reply: data.choices?.[0]?.message?.content || 'No reply' });
      } catch (e) {
        return json(res, 200, { reply: 'AI error: ' + e.message });
      }
    }

    // Fallback
    return json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('[ERR]', e.message, e.stack);
    return json(res, 500, { error: 'Internal error' });
  }
}