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
// Who is making this request? Permissions are read from the database on every request,
// so a role change or ban takes effect immediately, without the person logging in again.
async function getAuth(req) {
  if (ownerFromCookie(req)) return { owner: true, perms: new Set(PERM_KEYS) };
  const id = await userIdFromCookie(req);
  if (!id) return null;
  const db = await getDb();
  const u = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] })).rows[0];
  return u ? authForUser(u) : null;
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
async function readJson(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') return JSON.parse(req.body || '{}');
    if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString() || '{}');
    return req.body;
  }
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > 100_000) throw new Error('too large'); chunks.push(c); }
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
    return send(res, 201, sessionPayload(authForUser(u)), { 'Set-Cookie': sessionCookie(await makeUserToken(id)) });
  }

  if (pathname === '/api/login' && method === 'POST') {
    if (rateLimited(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }

    if (typeof body.username === 'string' && body.username.trim() !== '') {
      // account login
      const password = typeof body.password === 'string' ? body.password : '';
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
      return send(res, 200, { user: userForOwner(row) });
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

  /* ----- mod posts ----- */
  if (pathname === '/api/posts' && method === 'GET') {
    const db = await getDb();
    const r = await db.execute('SELECT * FROM posts ORDER BY id DESC');
    return send(res, 200, r.rows.map(rowToPost));
  }

  const m = pathname.match(/^\/api\/posts\/(\d+)$/);
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
