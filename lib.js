'use strict';
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { createClient } = require('@libsql/client');

const scrypt = promisify(crypto.scrypt);

const SESSION_TTL_S = 60 * 60 * 24 * 7; // 7 days
const STATUSES = ['Tested & Working', 'Not Tested', 'Not Working'];
const THEMES = ['summer', 'fall', 'winter', 'spring'];
const ANNOUNCE_TYPES = ['popup', 'bar'];
const ANNOUNCE_MAX = 500;

/* ---------- Roles & permissions ----------
   The owner (whoever knows ADMIN_PASSWORD) is not an account: they can do everything,
   and they are the only one who can manage accounts (roles, permissions, bans). */
const PERMISSIONS = [
  { key: 'post', label: 'Post new mods' },
  { key: 'edit', label: 'Edit mods' },
  { key: 'delete', label: 'Delete mods' },
  { key: 'announce', label: 'Send announcements' },
  { key: 'theme', label: 'Change site theme' },
  { key: 'inbox', label: 'Answer takedown & update requests' },
];
const PERM_KEYS = PERMISSIONS.map((p) => p.key);
const ROLES = {
  member: { label: 'Member', perms: [] },
  mod_maker: { label: 'Mod Maker', perms: ['post'] },
  moderator: { label: 'Moderator', perms: ['delete'] },
  admin: { label: 'Admin', perms: PERM_KEYS },
  custom: { label: 'Custom', perms: null }, // picked by the owner, stored per account
};
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_BAN_DAYS = 7;
const USERNAME_RE = /^[A-Za-z0-9_]{3,20}$/;

/* ---------- Database (libSQL: Turso in production, a local file in dev) ---------- */
let client;
let ready;
function getDb() {
  if (!client) {
    client = createClient({
      url: process.env.TURSO_DATABASE_URL || process.env.DATABASE_URL || 'file:shek.db',
      authToken: process.env.TURSO_AUTH_TOKEN || undefined,
    });
  }
  if (!ready) {
    ready = (async () => {
      await client.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
      await client.execute(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        username_lower TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'member',
        permissions TEXT NOT NULL DEFAULT '',
        banned_until INTEGER NOT NULL DEFAULT 0,
        ban_reason TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (date('now'))
      )`);
      await client.execute(`CREATE TABLE IF NOT EXISTS user_ips (
        user_id INTEGER NOT NULL,
        ip_hash TEXT NOT NULL,
        seen_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, ip_hash)
      )`);
      await client.execute(`CREATE TABLE IF NOT EXISTS ip_bans (
        ip_hash TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        until INTEGER NOT NULL,
        reason TEXT NOT NULL DEFAULT ''
      )`);
      await client.execute('CREATE INDEX IF NOT EXISTS ip_bans_hash ON ip_bans (ip_hash)');
      await client.execute(`CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        post_id INTEGER NOT NULL,
        post_title TEXT NOT NULL,
        type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        name TEXT NOT NULL,
        contact TEXT NOT NULL DEFAULT '',
        user_id INTEGER NOT NULL DEFAULT 0,
        unread INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )`);
      await client.execute(`CREATE TABLE IF NOT EXISTS request_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        sender TEXT NOT NULL,
        body TEXT NOT NULL,
        created_at INTEGER NOT NULL
      )`);
      await client.execute('CREATE INDEX IF NOT EXISTS request_messages_req ON request_messages (request_id)');
      await client.execute(`CREATE TABLE IF NOT EXISTS pages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        html TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (date('now'))
      )`);
      await client.execute(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        status TEXT NOT NULL,
        description TEXT NOT NULL,
        file_link TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (date('now'))
      )`);
      const n = Number((await client.execute('SELECT COUNT(*) AS n FROM posts')).rows[0].n);
      if (n === 0) {
        const seed = [
          ['Ultra Ray-Tracing Shaders FX', 'GfxGod', 'Tested & Working', 'Unlocks photorealistic global illumination, volumetric fog, and heavy SSR reflections. Tested on DirectX 12 engines.', 'https://example.com/mods/ultraraytracing.zip', '2026-09-24'],
          ['Speed Injector Tool v4.1', 'ShekDev', 'Not Tested', 'Memory tweak bypass for physics frame locking. High risk of desync; needs testing on public multiplayer servers.', 'https://example.com/files/speed_injector_v4.rar', '2026-09-25'],
          ['Legacy Menu HUD Patch', 'OldSchooler', 'Not Working', 'Restores the classic 2012 monochrome layout. Currently crashes on modern 1.4+ game patches. Needs fix.', 'https://example.com/patch/hud_legacy.7z', '2026-09-26'],
        ];
        for (const args of seed) {
          await client.execute({ sql: 'INSERT INTO posts (title, author, status, description, file_link, created_at) VALUES (?,?,?,?,?,?)', args });
        }
      }
    })().catch((e) => { ready = null; throw e; });
  }
  return ready.then(() => client);
}

/* ---------- Passwords (scrypt, salted) ---------- */
const DUMMY_SALT = Buffer.alloc(16, 7);
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return `${salt.toString('hex')}:${h.toString('hex')}`;
}
async function checkPw(pw, stored) {
  const [saltHex, hashHex] = String(stored).split(':');
  const expected = Buffer.from(hashHex || '', 'hex');
  if (!expected.length) return false;
  const actual = await scrypt(pw, Buffer.from(saltHex, 'hex'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

/* ---------- Auth: owner (ADMIN_PASSWORD) and accounts ---------- */
const sha = (s) => crypto.createHash('sha256').update(s).digest();
function ownerPasswordOk(input) {
  const real = process.env.ADMIN_PASSWORD;
  if (!real || typeof input !== 'string') return false;
  return crypto.timingSafeEqual(sha(input), sha(real));
}
function sigKey() {
  return sha('shek-session:' + (process.env.SESSION_SECRET || '') + ':' + (process.env.ADMIN_PASSWORD || ''));
}
function makeToken() {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_S;
  const body = `v1.${exp}`;
  const sig = crypto.createHmac('sha256', sigKey()).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function ownerFromCookie(req) {
  if (!process.env.ADMIN_PASSWORD) return false;
  const token = parseCookies(req).shek_session;
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return false;
  const expected = crypto.createHmac('sha256', sigKey()).update(`${parts[0]}.${parts[1]}`).digest();
  let given; try { given = Buffer.from(parts[2], 'base64url'); } catch { return false; }
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return false;
  return Number(parts[1]) > Date.now() / 1000;
}

// Account sessions are signed with a random key kept in the database, so anyone who signs up
// (and so holds a signed cookie) can never use it to work out ADMIN_PASSWORD or SESSION_SECRET.
let userKeyCache;
async function getUserKey() {
  if (userKeyCache) return userKeyCache;
  const db = await getDb();
  const read = () => db.execute({ sql: 'SELECT value FROM settings WHERE key = ?', args: ['user_session_key'] });
  let r = await read();
  if (!r.rows[0]) {
    await db.execute({ sql: 'INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', args: ['user_session_key', crypto.randomBytes(32).toString('hex')] });
    r = await read();
  }
  userKeyCache = Buffer.from(String(r.rows[0].value), 'hex');
  return userKeyCache;
}
async function makeUserToken(id) {
  const body = `u1.${id}.${Math.floor(Date.now() / 1000) + SESSION_TTL_S}`;
  const sig = crypto.createHmac('sha256', await getUserKey()).update(body).digest('base64url');
  return `${body}.${sig}`;
}
async function userIdFromCookie(req) {
  const token = parseCookies(req).shek_session;
  if (!token) return null;
  const p = token.split('.');
  if (p.length !== 4 || p[0] !== 'u1') return null;
  const expected = crypto.createHmac('sha256', await getUserKey()).update(`${p[0]}.${p[1]}.${p[2]}`).digest();
  let given; try { given = Buffer.from(p[3], 'base64url'); } catch { return null; }
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  if (!(Number(p[2]) > Date.now() / 1000)) return null;
  const id = Number(p[1]);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function effectivePerms(u) {
  const role = ROLES[u.role] ? u.role : 'member';
  if (role === 'custom') return String(u.permissions || '').split(',').filter((p) => PERM_KEYS.includes(p));
  return ROLES[role].perms.slice();
}
function authForUser(u) {
  const until = Number(u.banned_until);
  if (until > Date.now()) return { owner: false, banned: { until, reason: String(u.ban_reason || '') }, perms: new Set() };
  return { owner: false, user: u, perms: new Set(effectivePerms(u)) };
}
/* ---------- IP tracking (for bans) ----------
   Only a keyed hash of the connection is stored, never the raw address. When the owner bans an
   account, the connections that account used in the last 24 hours are banned for the same time. */
const IP_WINDOW_MS = 24 * 60 * 60 * 1000;
function clientIp(req) {
  const h = req.headers;
  const raw = String(h['x-vercel-forwarded-for'] || h['x-real-ip'] || (h['x-forwarded-for'] || '').split(',')[0] || (req.socket && req.socket.remoteAddress) || '').trim();
  return raw.replace(/^::ffff:/i, '');
}
function normalizeIp(ip) {
  if (!ip.includes(':')) return ip;                       // IPv4
  // IPv6: people get a whole /64, so keep the first 4 groups
  let [head, tail] = ip.split('::');
  const a = head ? head.split(':') : [];
  const b = tail !== undefined && tail ? tail.split(':') : [];
  const groups = tail === undefined ? a : [...a, ...Array(Math.max(0, 8 - a.length - b.length)).fill('0'), ...b];
  return groups.slice(0, 4).map((g) => (g || '0').toLowerCase().replace(/^0+(?=.)/, '')).join(':');
}
function ipHash(req) {
  const ip = clientIp(req);
  if (!ip) return '';
  const key = 'ipban:' + (process.env.SESSION_SECRET || '') + ':' + (process.env.ADMIN_PASSWORD || '');
  return crypto.createHmac('sha256', key).update(normalizeIp(ip)).digest('base64url').slice(0, 22);
}
async function ipBanFor(req) {
  const h = ipHash(req);
  if (!h) return null;
  const db = await getDb();
  const r = (await db.execute({ sql: 'SELECT until, reason FROM ip_bans WHERE ip_hash = ? AND until > ? ORDER BY until DESC LIMIT 1', args: [h, Date.now()] })).rows[0];
  return r ? { until: Number(r.until), reason: String(r.reason || '') } : null;
}
const ipSeen = new Map();
async function recordIp(userId, req) {
  const h = ipHash(req);
  if (!h) return;
  const key = userId + ':' + h, now = Date.now();
  if (now - (ipSeen.get(key) || 0) < 30 * 60 * 1000) return;       // at most one write per 30 min
  ipSeen.set(key, now);
  if (ipSeen.size > 5000) ipSeen.clear();
  const db = await getDb();
  await db.execute({ sql: 'INSERT INTO user_ips (user_id, ip_hash, seen_at) VALUES (?,?,?) ON CONFLICT(user_id, ip_hash) DO UPDATE SET seen_at = excluded.seen_at', args: [userId, h, now] });
  if (Math.random() < 0.02) {                                       // tidy up old rows now and then
    await db.execute({ sql: 'DELETE FROM user_ips WHERE seen_at < ?', args: [now - 7 * 24 * 60 * 60 * 1000] }).catch(() => {});
    await db.execute({ sql: 'DELETE FROM ip_bans WHERE until < ?', args: [now] }).catch(() => {});
  }
}

// Who is making this request? Permissions are read from the database on every request,
// so a role change or ban takes effect immediately, without the person logging in again.
// A banned connection is treated as banned even when nobody is logged in.
async function getAuth(req) {
  if (ownerFromCookie(req)) return { owner: true, perms: new Set(PERM_KEYS) };
  let auth = null;
  const id = await userIdFromCookie(req);
  if (id) {
    const db = await getDb();
    const u = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] })).rows[0];
    auth = u ? authForUser(u) : null;
  }
  if (!auth || !auth.banned) {
    const ipb = await ipBanFor(req);
    if (ipb) return { owner: false, banned: ipb, ipBanned: true, perms: new Set() };
  }
  if (auth && auth.user) await recordIp(Number(auth.user.id), req).catch(() => {});
  return auth;
}
function sessionPayload(auth) {
  if (!auth) return { admin: false, owner: false, user: null, permissions: [] };
  if (auth.owner) return { admin: true, owner: true, user: null, permissions: [...auth.perms] };
  if (auth.banned) return { admin: false, owner: false, user: null, permissions: [], banned: auth.banned };
  const role = ROLES[auth.user.role] ? auth.user.role : 'member';
  return {
    admin: false, owner: false,
    user: { id: Number(auth.user.id), username: auth.user.username, role, roleLabel: ROLES[role].label },
    permissions: [...auth.perms],
  };
}
function userForOwner(u) {
  const until = Number(u.banned_until);
  const banned = until > Date.now();
  const role = ROLES[u.role] ? u.role : 'member';
  return {
    id: Number(u.id), username: u.username, role, roleLabel: ROLES[role].label,
    permissions: effectivePerms(u),
    bannedUntil: banned ? until : 0, banReason: banned ? String(u.ban_reason || '') : '',
    createdAt: u.created_at,
  };
}
const banMessage = (b) => `You are banned until ${new Date(b.until).toUTCString()}.` + (b.reason ? ` Reason: ${b.reason}` : '');

/* ---------- Rate limits (best effort: per warm serverless instance) ---------- */
const attempts = new Map();
const rateLimited = (ip) => {
  const now = Date.now();
  const rec = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  attempts.set(ip, rec);
  return rec.length >= 8;
};
const recordFailure = (ip) => attempts.get(ip).push(Date.now());
const reqRate = new Map();    // per connection: new requests (6/hour) and lookups/replies (60/10 min)
function reqLimited(ip, kind) {
  const win = kind === 'new' ? 60 * 60 * 1000 : 10 * 60 * 1000, max = kind === 'new' ? 6 : 60;
  const key = kind + ':' + ip, now = Date.now();
  const rec = (reqRate.get(key) || []).filter((t) => now - t < win);
  if (rec.length >= max) { reqRate.set(key, rec); return true; }
  rec.push(now); reqRate.set(key, rec);
  if (reqRate.size > 5000) reqRate.clear();
  return false;
}
const REQ_TYPES = ['takedown', 'update'];
const REQ_MSG_MAX = 3000;
const REQ_THREAD_MAX = 40;
const newCode = () => {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return 'SM-' + Array.from(crypto.randomBytes(10), (b) => alphabet[b % alphabet.length]).join('');
};
const cleanText = (v, max) => (typeof v === 'string' ? v.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, max) : '');
const rowToMsg = (m) => ({ id: Number(m.id), from: m.sender === 'dev' ? 'dev' : 'user', body: m.body, time: Number(m.created_at) });
async function loadThread(db, row, forOwner) {
  const msgs = (await db.execute({ sql: 'SELECT * FROM request_messages WHERE request_id = ? ORDER BY id ASC', args: [Number(row.id)] })).rows.map(rowToMsg);
  return {
    id: Number(row.id), ...(forOwner ? {} : { code: row.code }), postId: Number(row.post_id), postTitle: row.post_title,
    type: row.type, status: row.status, name: row.name, ...(forOwner ? { contact: row.contact, userId: Number(row.user_id), code: row.code } : {}),
    createdAt: Number(row.created_at), updatedAt: Number(row.updated_at), messages: msgs,
  };
}
const signups = new Map();
const signupLimited = (ip) => {
  const now = Date.now();
  const rec = (signups.get(ip) || []).filter((t) => now - t < 60 * 60 * 1000);
  signups.set(ip, rec);
  return rec.length >= 5;
};

/* ---------- Helpers ---------- */
function send(res, code, body, headers = {}) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}
function sendHtml(res, code, html) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-cache');
  // Owner-made pages run in a sandbox: scripts, forms and popups work, but the page can never
  // touch this site's login cookie or API (opaque origin).
  res.setHeader('Content-Security-Policy', 'sandbox allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads');
  res.end(html);
}
const PAGE_MAX = 1_000_000;
function slugify(t) {
  return String(t).toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50).replace(/-+$/, '') || 'page';
}
function validatePage(b) {
  const title = typeof b.title === 'string' ? b.title.trim().slice(0, 120) : '';
  const html = typeof b.html === 'string' ? b.html : '';
  if (!title) return { error: 'Give the page a title.' };
  if (!html.trim()) return { error: 'Paste some HTML.' };
  if (html.length > PAGE_MAX) return { error: 'That HTML is too big (max ~1 MB).' };
  return { title, html };
}
async function readJson(req, max = 100_000) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') return JSON.parse(req.body || '{}');
    if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString() || '{}');
    return req.body;
  }
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > max) throw new Error('too large'); chunks.push(c); }
  return JSON.parse(Buffer.concat(chunks).toString() || '{}');
}
function badOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  let host; try { host = new URL(origin).host; } catch { host = ''; }
  return host !== req.headers.host;
}
// Sends the right error and returns false when the caller may not do `perm`.
function requirePerm(res, auth, perm) {
  if (auth && auth.perms.has(perm)) return true;
  if (!auth) send(res, 401, { error: 'Log in first.' });
  else if (auth.banned) send(res, 403, { error: banMessage(auth.banned), banned: auth.banned });
  else send(res, 403, { error: "You don't have permission to do that." });
  return false;
}
function requireOwner(res, auth) {
  if (auth && auth.owner) return true;
  if (!auth) send(res, 401, { error: 'Log in first.' });
  else send(res, 403, { error: 'Only the owner can do that.' });
  return false;
}
function validatePost(b) {
  const clean = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
  const post = {
    title: clean(b.title, 120), author: clean(b.author, 60), status: clean(b.status, 30),
    description: clean(b.description, 2000), file_link: clean(b.file_link, 500),
  };
  if (!post.title || !post.author || !post.description || !post.file_link) return { error: 'All fields are required.' };
  if (!STATUSES.includes(post.status)) return { error: 'Invalid status.' };
  if (/^[a-z][a-z0-9+.-]*:/i.test(post.file_link) && !/^https?:\/\//i.test(post.file_link)) return { error: 'File link must be an http(s) URL or a filename.' };
  return { post };
}
const rowToPost = (r) => ({ id: Number(r.id), title: r.title, author: r.author, status: r.status, desc: r.description, fileLink: r.file_link, date: r.created_at });

/* ---------- API handler ---------- */
async function handleApi(req, res) {
  const url = new URL(req.url, 'http://localhost');
  // On Vercel the rewrite sends /api/<route> to this function with ?route=<route>,
  // so the original path is recovered from there (locally it's just the URL path).
  let route = req.query && req.query.route !== undefined ? req.query.route : url.searchParams.get('route');
  if (Array.isArray(route)) route = route.join('/');
  const pathname = (route !== null && route !== undefined ? '/api/' + route : url.pathname).replace(/\/+$/, '');
  const method = req.method;
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  const secure = process.env.VERCEL || process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const sessionCookie = (token) => `shek_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_S}${secure}`;

  /* ----- session, sign-up, login, logout ----- */
  if (pathname === '/api/session' && method === 'GET') return send(res, 200, sessionPayload(await getAuth(req)));

  if (pathname === '/api/register' && method === 'POST') {
    if (signupLimited(ip)) return send(res, 429, { error: 'Too many sign-ups from your connection. Try again later.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!USERNAME_RE.test(username)) return send(res, 400, { error: 'Username must be 3-20 characters: letters, numbers and underscores only.' });
    if (password.length < 8 || password.length > 128) return send(res, 400, { error: 'Password must be 8-128 characters.' });
    const ipb = await ipBanFor(req);
    if (ipb) return send(res, 403, { error: banMessage(ipb), banned: ipb });
    signups.get(ip).push(Date.now());
    const db = await getDb();
    const hash = await hashPw(password);
    let ins;
    try {
      ins = await db.execute({ sql: 'INSERT INTO users (username, username_lower, password_hash) VALUES (?,?,?)', args: [username, username.toLowerCase(), hash] });
    } catch (e) {
      if (/UNIQUE|constraint/i.test(String(e && e.message))) return send(res, 409, { error: 'That username is already taken.' });
      throw e;
    }
    const id = Number(ins.lastInsertRowid);
    const u = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] })).rows[0];
    await recordIp(id, req).catch(() => {});
    return send(res, 201, sessionPayload(authForUser(u)), { 'Set-Cookie': sessionCookie(await makeUserToken(id)) });
  }

  if (pathname === '/api/login' && method === 'POST') {
    if (rateLimited(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }

    if (typeof body.username === 'string' && body.username.trim() !== '') {
      // account login
      const password = typeof body.password === 'string' ? body.password : '';
      const ipb = await ipBanFor(req);
      if (ipb) return send(res, 403, { error: banMessage(ipb), banned: ipb });
      const db = await getDb();
      const u = (await db.execute({ sql: 'SELECT * FROM users WHERE username_lower = ?', args: [body.username.trim().toLowerCase()] })).rows[0];
      let ok = false;
      if (password.length <= 128) {
        if (u) ok = await checkPw(password, u.password_hash);
        else await scrypt(password, DUMMY_SALT, 64); // same work either way, so timing doesn't reveal which usernames exist
      }
      if (!ok) { recordFailure(ip); return send(res, 401, { error: 'Invalid username or password.' }); }
      const auth = authForUser(u);
      if (auth.banned) return send(res, 403, { error: banMessage(auth.banned), banned: auth.banned });
      await recordIp(Number(u.id), req).catch(() => {});
      return send(res, 200, sessionPayload(auth), { 'Set-Cookie': sessionCookie(await makeUserToken(Number(u.id))) });
    }

    // owner login (ADMIN_PASSWORD)
    if (!process.env.ADMIN_PASSWORD) return send(res, 500, { error: 'Server is missing the ADMIN_PASSWORD environment variable.' });
    if (!ownerPasswordOk(body.password)) { recordFailure(ip); return send(res, 401, { error: 'Invalid passcode.' }); }
    return send(res, 200, sessionPayload({ owner: true, perms: new Set(PERM_KEYS) }), { 'Set-Cookie': sessionCookie(makeToken()) });
  }

  if (pathname === '/api/logout' && method === 'POST') {
    return send(res, 200, sessionPayload(null), { 'Set-Cookie': `shek_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}` });
  }

  /* ----- account management (owner only): roles, permissions, bans ----- */
  const um = pathname.match(/^\/api\/users\/(\d+)$/);
  if (pathname === '/api/users' || um) {
    const auth = await getAuth(req);
    if (!requireOwner(res, auth)) return;
    if (badOrigin(req)) return send(res, 403, { error: 'Bad origin.' });
    const db = await getDb();

    if (pathname === '/api/users' && method === 'GET') {
      const rows = (await db.execute('SELECT * FROM users ORDER BY id DESC')).rows;
      const roles = Object.fromEntries(Object.entries(ROLES).map(([k, r]) => [k, { label: r.label, perms: r.perms }]));
      return send(res, 200, { users: rows.map(userForOwner), roles, permissions: PERMISSIONS, maxBanDays: MAX_BAN_DAYS });
    }

    if (um && method === 'PATCH') {
      let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
      const sets = []; const args = [];

      if (body.role !== undefined) {
        if (typeof body.role !== 'string' || !ROLES[body.role]) return send(res, 400, { error: 'Unknown role.' });
        let list = '';
        if (body.role === 'custom') {
          if (!Array.isArray(body.permissions) || !body.permissions.every((p) => typeof p === 'string' && PERM_KEYS.includes(p))) return send(res, 400, { error: 'Unknown permission.' });
          list = [...new Set(body.permissions)].join(',');
        }
        sets.push('role = ?', 'permissions = ?'); args.push(body.role, list);
      }

      if (body.unban === true && body.ban !== undefined) return send(res, 400, { error: 'Choose either ban or unban.' });
      if (body.unban === true) {
        sets.push('banned_until = 0', "ban_reason = ''");
      } else if (body.ban !== undefined) {
        const b = body.ban && typeof body.ban === 'object' ? body.ban : {};
        const days = Number(b.days);
        if (!Number.isInteger(days) || days < 1 || days > MAX_BAN_DAYS) return send(res, 400, { error: `Ban length must be 1 to ${MAX_BAN_DAYS} days.` });
        const reason = typeof b.reason === 'string' ? b.reason.trim().slice(0, 200) : '';
        sets.push('banned_until = ?', 'ban_reason = ?'); args.push(Date.now() + days * DAY_MS, reason);
      }

      if (!sets.length) return send(res, 400, { error: 'Nothing to change.' });
      const up = await db.execute({ sql: `UPDATE users SET ${sets.join(', ')} WHERE id = ?`, args: [...args, Number(um[1])] });
      if (!up.rowsAffected) return send(res, 404, { error: 'No such account.' });
      const row = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [Number(um[1])] })).rows[0];
      let ipsBanned = 0;
      if (body.unban === true) {
        await db.execute({ sql: 'DELETE FROM ip_bans WHERE user_id = ?', args: [Number(um[1])] });
      } else if (body.ban !== undefined) {
        await db.execute({ sql: 'DELETE FROM ip_bans WHERE user_id = ?', args: [Number(um[1])] });
        const blockIps = !(body.ban && body.ban.ip === false);   // the owner can untick "also block their connection"
        const seen = !blockIps ? [] : (await db.execute({ sql: 'SELECT ip_hash FROM user_ips WHERE user_id = ? AND seen_at > ?', args: [Number(um[1]), Date.now() - IP_WINDOW_MS] })).rows;
        for (const r of seen) {
          await db.execute({ sql: 'INSERT INTO ip_bans (ip_hash, user_id, until, reason) VALUES (?,?,?,?)', args: [r.ip_hash, Number(um[1]), Number(row.banned_until), String(row.ban_reason || '')] });
        }
        ipsBanned = seen.length;
      }
      return send(res, 200, { user: userForOwner(row), ipsBanned });
    }
  }

  /* ----- site theme ----- */
  if (pathname === '/api/theme' && method === 'GET') {
    const db = await getDb();
    const r = await db.execute({ sql: 'SELECT value FROM settings WHERE key = ?', args: ['theme'] });
    const t = r.rows[0] && THEMES.includes(r.rows[0].value) ? r.rows[0].value : 'summer';
    return send(res, 200, { theme: t, themes: THEMES });
  }

  if (pathname === '/api/theme' && method === 'PUT') {
    if (!requirePerm(res, await getAuth(req), 'theme')) return;
    if (badOrigin(req)) return send(res, 403, { error: 'Bad origin.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    if (!THEMES.includes(body.theme)) return send(res, 400, { error: 'Unknown theme.' });
    const db = await getDb();
    await db.execute({ sql: 'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', args: ['theme', body.theme] });
    return send(res, 200, { theme: body.theme });
  }

  /* ----- announcements ----- */
  if (pathname === '/api/announcement' && method === 'GET') {
    const db = await getDb();
    const r = await db.execute({ sql: 'SELECT value FROM settings WHERE key = ?', args: ['announcement'] });
    let a = null;
    try { a = r.rows[0] ? JSON.parse(r.rows[0].value) : null; } catch { a = null; }
    if (!a || !ANNOUNCE_TYPES.includes(a.type) || typeof a.message !== 'string' || !a.message) return send(res, 200, { active: false });
    return send(res, 200, { active: true, id: String(a.id), type: a.type, message: a.message });
  }

  if (pathname === '/api/announcement' && (method === 'PUT' || method === 'DELETE')) {
    if (!requirePerm(res, await getAuth(req), 'announce')) return;
    if (badOrigin(req)) return send(res, 403, { error: 'Bad origin.' });
    const db = await getDb();
    if (method === 'DELETE') {
      await db.execute({ sql: 'DELETE FROM settings WHERE key = ?', args: ['announcement'] });
      return send(res, 200, { active: false });
    }
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    const type = typeof body.type === 'string' ? body.type : '';
    const message = typeof body.message === 'string' ? body.message.trim().slice(0, ANNOUNCE_MAX) : '';
    if (!ANNOUNCE_TYPES.includes(type)) return send(res, 400, { error: 'Type must be "popup" or "bar".' });
    if (!message) return send(res, 400, { error: 'Write an announcement first.' });
    // a fresh id on every publish, so a pop-up shows again to people who closed the previous one
    const a = { id: Date.now().toString(36) + crypto.randomBytes(3).toString('hex'), type, message };
    await db.execute({ sql: 'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', args: ['announcement', JSON.stringify(a)] });
    return send(res, 200, { active: true, ...a });
  }

  /* ----- custom pages (owner-made, permanent, served at /p/<slug>) ----- */
  let pm = pathname.match(/^\/api\/p\/([a-z0-9-]{1,60})$/);
  if (pm && method === 'GET') {
    if (String(req.headers.host || '').toLowerCase().split(':')[0] === 'apkmodding.vercel.app') {
      res.statusCode = 302; res.setHeader('Location', '/moved/?p=' + encodeURIComponent('/p/' + pm[1])); return res.end();
    }
    const db = await getDb();
    const r = await db.execute({ sql: 'SELECT html FROM pages WHERE slug = ?', args: [pm[1]] });
    if (!r.rows.length) return sendHtml(res, 404, '<!DOCTYPE html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Not found</title><body style="background:#000;color:#22ff66;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center"><div>Page not found.<br><br><a style="color:#22ff66" href="/">Home</a></div>');
    return sendHtml(res, 200, String(r.rows[0].html));
  }
  pm = pathname.match(/^\/api\/pages(?:\/(\d+))?$/);
  if (pm) {
    const auth = await getAuth(req);
    if (!requireOwner(res, auth)) return;
    if (method !== 'GET' && badOrigin(req)) return send(res, 403, { error: 'Bad origin.' });
    const db = await getDb();
    const id = pm[1] ? Number(pm[1]) : null;
    const toPage = (r, withHtml) => ({ id: Number(r.id), slug: r.slug, title: r.title, date: r.created_at, ...(withHtml ? { html: r.html } : {}) });
    if (method === 'GET' && !id) {
      const r = await db.execute('SELECT id, slug, title, created_at FROM pages ORDER BY id DESC');
      return send(res, 200, r.rows.map((x) => toPage(x, false)));
    }
    if (method === 'GET') {
      const r = await db.execute({ sql: 'SELECT * FROM pages WHERE id = ?', args: [id] });
      return r.rows.length ? send(res, 200, toPage(r.rows[0], true)) : send(res, 404, { error: 'Not found.' });
    }
    if (method === 'POST' && !id) {
      let body; try { body = await readJson(req, PAGE_MAX + 50_000); } catch { return send(res, 400, { error: 'Bad request (HTML too big?).' }); }
      const v = validatePage(body);
      if (v.error) return send(res, 400, { error: v.error });
      const base = slugify(v.title);
      for (let i = 1; i <= 50; i++) {
        const slug = i === 1 ? base : `${base}-${i}`;
        try {
          const ins = await db.execute({ sql: 'INSERT INTO pages (slug, title, html) VALUES (?,?,?)', args: [slug, v.title, v.html] });
          const row = (await db.execute({ sql: 'SELECT * FROM pages WHERE id = ?', args: [Number(ins.lastInsertRowid)] })).rows[0];
          return send(res, 201, toPage(row, false));
        } catch (e) {
          if (!/unique|constraint/i.test(String(e && e.message))) throw e;
        }
      }
      return send(res, 409, { error: 'Could not find a free link for that title.' });
    }
    if (method === 'PUT' && id) {
      let body; try { body = await readJson(req, PAGE_MAX + 50_000); } catch { return send(res, 400, { error: 'Bad request (HTML too big?).' }); }
      const v = validatePage(body);
      if (v.error) return send(res, 400, { error: v.error });
      const up = await db.execute({ sql: 'UPDATE pages SET title = ?, html = ? WHERE id = ?', args: [v.title, v.html, id] });
      if (!up.rowsAffected) return send(res, 404, { error: 'Not found.' });
      const row = (await db.execute({ sql: 'SELECT * FROM pages WHERE id = ?', args: [id] })).rows[0];
      return send(res, 200, toPage(row, false));
    }
    if (method === 'DELETE' && id) {
      const del = await db.execute({ sql: 'DELETE FROM pages WHERE id = ?', args: [id] });
      return send(res, del.rowsAffected ? 200 : 404, { ok: !!del.rowsAffected });
    }
  }

  /* ----- takedown / update requests (a small "mailbox" between visitors and the developer) ----- */
  if (pathname === '/api/requests' && method === 'POST') {
    if (badOrigin(req)) return send(res, 403, { error: 'Bad origin.' });
    const auth = await getAuth(req);
    if (auth && auth.banned) return send(res, 403, { error: banMessage(auth.banned), banned: auth.banned });
    if (reqLimited(ip, 'new')) return send(res, 429, { error: 'You have sent a lot of requests. Try again in a while.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    if (typeof body.website === 'string' && body.website.trim() !== '') return send(res, 201, { code: newCode(), id: 0 });   // honeypot: bots fill this in
    const type = REQ_TYPES.includes(body.type) ? body.type : '';
    if (!type) return send(res, 400, { error: 'Choose takedown or update.' });
    const message = cleanText(body.message, REQ_MSG_MAX);
    if (message.length < 10) return send(res, 400, { error: 'Please write a little more (at least 10 characters).' });
    const db = await getDb();
    const post = (await db.execute({ sql: 'SELECT id, title FROM posts WHERE id = ?', args: [Number(body.postId)] })).rows[0];
    if (!post) return send(res, 404, { error: 'That mod no longer exists.' });
    let name = cleanText(body.name, 40) || 'Anonymous', userId = 0;
    if (auth && auth.owner) name = 'Owner';
    else if (auth && auth.user) { name = auth.user.username; userId = Number(auth.user.id); }
    const contact = cleanText(body.contact, 120);
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      const code = newCode();
      try {
        const ins = await db.execute({ sql: 'INSERT INTO requests (code, post_id, post_title, type, name, contact, user_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)', args: [code, Number(post.id), String(post.title), type, name, contact, userId, now, now] });
        await db.execute({ sql: 'INSERT INTO request_messages (request_id, sender, body, created_at) VALUES (?,?,?,?)', args: [Number(ins.lastInsertRowid), 'user', message, now] });
        return send(res, 201, { code, id: Number(ins.lastInsertRowid) });
      } catch (e) { if (!/unique|constraint/i.test(String(e && e.message))) throw e; }
    }
    return send(res, 500, { error: 'Could not create the request. Try again.' });
  }

  if (pathname === '/api/requests/lookup' && method === 'POST') {      // requester checks their own tickets by code
    if (reqLimited(ip, 'lookup')) return send(res, 429, { error: 'Too many checks. Wait a few minutes.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    const codes = (Array.isArray(body.codes) ? body.codes : []).filter((c) => typeof c === 'string' && /^SM-[A-Z2-9]{10}$/.test(c.trim().toUpperCase())).map((c) => c.trim().toUpperCase()).slice(0, 20);
    const db = await getDb();
    const out = [];
    for (const code of [...new Set(codes)]) {
      const row = (await db.execute({ sql: 'SELECT * FROM requests WHERE code = ?', args: [code] })).rows[0];
      if (row) out.push(await loadThread(db, row, false));
    }
    return send(res, 200, { threads: out });
  }

  if (pathname === '/api/requests/reply' && method === 'POST') {       // requester adds a follow-up
    if (badOrigin(req)) return send(res, 403, { error: 'Bad origin.' });
    if (reqLimited(ip, 'lookup')) return send(res, 429, { error: 'Too many messages. Wait a few minutes.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    const code = typeof body.code === 'string' ? body.code.trim().toUpperCase() : '';
    const message = cleanText(body.body, REQ_MSG_MAX);
    if (!/^SM-[A-Z2-9]{10}$/.test(code)) return send(res, 400, { error: 'Bad ticket code.' });
    if (!message) return send(res, 400, { error: 'Write a message first.' });
    const auth = await getAuth(req);
    if (auth && auth.banned) return send(res, 403, { error: banMessage(auth.banned), banned: auth.banned });
    const db = await getDb();
    const row = (await db.execute({ sql: 'SELECT * FROM requests WHERE code = ?', args: [code] })).rows[0];
    if (!row) return send(res, 404, { error: 'No request with that code.' });
    if (row.status === 'closed') return send(res, 409, { error: 'This request is closed.' });
    const n = Number((await db.execute({ sql: 'SELECT COUNT(*) AS n FROM request_messages WHERE request_id = ?', args: [Number(row.id)] })).rows[0].n);
    if (n >= REQ_THREAD_MAX) return send(res, 409, { error: 'This conversation is full. Please open a new request.' });
    const now = Date.now();
    await db.execute({ sql: 'INSERT INTO request_messages (request_id, sender, body, created_at) VALUES (?,?,?,?)', args: [Number(row.id), 'user', message, now] });
    await db.execute({ sql: 'UPDATE requests SET unread = 1, updated_at = ? WHERE id = ?', args: [now, Number(row.id)] });
    return send(res, 200, await loadThread(db, row, false));
  }

  const ib = pathname.match(/^\/api\/inbox(?:\/(\d+)(\/reply)?)?$/);
  if (ib) {                                                           // the developer's inbox
    if (!requirePerm(res, await getAuth(req), 'inbox')) return;
    if (method !== 'GET' && badOrigin(req)) return send(res, 403, { error: 'Bad origin.' });
    const db = await getDb();
    const id = ib[1] ? Number(ib[1]) : null;
    if (!id && method === 'GET') {
      const rows = (await db.execute(`SELECT r.*, (SELECT body FROM request_messages m WHERE m.request_id = r.id ORDER BY m.id DESC LIMIT 1) AS snippet,
        (SELECT sender FROM request_messages m WHERE m.request_id = r.id ORDER BY m.id DESC LIMIT 1) AS last_from
        FROM requests r ORDER BY (r.status = 'open') DESC, r.updated_at DESC LIMIT 300`)).rows;
      const items = rows.map((r) => ({
        id: Number(r.id), type: r.type, status: r.status, postId: Number(r.post_id), postTitle: r.post_title, name: r.name,
        unread: !!Number(r.unread), awaitingReply: r.status === 'open' && r.last_from === 'user',
        snippet: String(r.snippet || '').slice(0, 140), updatedAt: Number(r.updated_at), createdAt: Number(r.created_at),
      }));
      return send(res, 200, { items, unread: items.filter((i) => i.unread).length });
    }
    if (!id) return send(res, 404, { error: 'Not found.' });
    const row = (await db.execute({ sql: 'SELECT * FROM requests WHERE id = ?', args: [id] })).rows[0];
    if (!row) return send(res, 404, { error: 'Not found.' });
    if (!ib[2] && method === 'GET') {
      await db.execute({ sql: 'UPDATE requests SET unread = 0 WHERE id = ?', args: [id] });
      return send(res, 200, await loadThread(db, row, true));
    }
    if (ib[2] && method === 'POST') {
      let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
      const message = cleanText(body.body, REQ_MSG_MAX);
      if (!message) return send(res, 400, { error: 'Write a reply first.' });
      const now = Date.now();
      await db.execute({ sql: 'INSERT INTO request_messages (request_id, sender, body, created_at) VALUES (?,?,?,?)', args: [id, 'dev', message, now] });
      await db.execute({ sql: 'UPDATE requests SET unread = 0, updated_at = ? WHERE id = ?', args: [now, id] });
      return send(res, 200, await loadThread(db, row, true));
    }
    if (!ib[2] && method === 'PATCH') {
      let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
      if (body.status !== 'open' && body.status !== 'closed') return send(res, 400, { error: 'Bad status.' });
      await db.execute({ sql: 'UPDATE requests SET status = ?, updated_at = ? WHERE id = ?', args: [body.status, Date.now(), id] });
      return send(res, 200, { ok: true, status: body.status });
    }
    if (!ib[2] && method === 'DELETE') {
      await db.execute({ sql: 'DELETE FROM request_messages WHERE request_id = ?', args: [id] });
      await db.execute({ sql: 'DELETE FROM requests WHERE id = ?', args: [id] });
      return send(res, 200, { ok: true });
    }
  }

  /* ----- mod posts ----- */
  const lockedOut = async () => {   // banned accounts can't see the mods
    const a = await getAuth(req);
    if (a && a.banned) { send(res, 403, { error: banMessage(a.banned), banned: a.banned }); return true; }
    return false;
  };
  if (pathname === '/api/posts' && method === 'GET') {
    if (await lockedOut()) return;
    const db = await getDb();
    const r = await db.execute('SELECT * FROM posts ORDER BY id DESC');
    return send(res, 200, r.rows.map(rowToPost));
  }

  const m = pathname.match(/^\/api\/posts\/(\d+)$/);
  if (m && method === 'GET') {
    if (await lockedOut()) return;
    const db = await getDb();
    const r = await db.execute({ sql: 'SELECT * FROM posts WHERE id = ?', args: [Number(m[1])] });
    return r.rows.length ? send(res, 200, rowToPost(r.rows[0])) : send(res, 404, { error: 'Not found.' });
  }
  if ((pathname === '/api/posts' && method === 'POST') || (m && (method === 'PUT' || method === 'DELETE'))) {
    const need = !m ? 'post' : method === 'PUT' ? 'edit' : 'delete';
    if (!requirePerm(res, await getAuth(req), need)) return;
    if (badOrigin(req)) return send(res, 403, { error: 'Bad origin.' });
    const db = await getDb();

    if (!m) {
      let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
      const { post, error } = validatePost(body);
      if (error) return send(res, 400, { error });
      const ins = await db.execute({ sql: 'INSERT INTO posts (title, author, status, description, file_link) VALUES (?,?,?,?,?)', args: [post.title, post.author, post.status, post.description, post.file_link] });
      const row = (await db.execute({ sql: 'SELECT * FROM posts WHERE id = ?', args: [Number(ins.lastInsertRowid)] })).rows[0];
      return send(res, 201, rowToPost(row));
    }
    if (method === 'PUT') {
      let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
      const { post, error } = validatePost(body);
      if (error) return send(res, 400, { error });
      const up = await db.execute({ sql: 'UPDATE posts SET title=?, author=?, status=?, description=?, file_link=? WHERE id=?', args: [post.title, post.author, post.status, post.description, post.file_link, Number(m[1])] });
      if (!up.rowsAffected) return send(res, 404, { error: 'Not found.' });
      const row = (await db.execute({ sql: 'SELECT * FROM posts WHERE id = ?', args: [Number(m[1])] })).rows[0];
      return send(res, 200, rowToPost(row));
    }
    const del = await db.execute({ sql: 'DELETE FROM posts WHERE id = ?', args: [Number(m[1])] });
    return send(res, del.rowsAffected ? 200 : 404, { ok: !!del.rowsAffected });
  }
  return send(res, 404, { error: 'Not found.' });
}

module.exports = async function handler(req, res) {
  try { await handleApi(req, res); }
  catch (e) { console.error(e); send(res, 500, { error: 'Server error: ' + (e && e.message ? e.message : 'unknown') }); }
};
