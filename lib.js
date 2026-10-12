'use strict';
const crypto = require('node:crypto');
const { createClient } = require('@libsql/client');

const SESSION_TTL_S = 60 * 60 * 24 * 7; // 7 days
const STATUSES = ['Tested & Working', 'Not Tested', 'Not Working'];

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

/* ---------- Auth: password from env, stateless HMAC-signed session cookie ---------- */
const sha = (s) => crypto.createHash('sha256').update(s).digest();
function passwordOk(input) {
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
function isAdmin(req) {
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

/* ---------- Login rate limit (best effort: per warm serverless instance) ---------- */
const attempts = new Map();
const rateLimited = (ip) => {
  const now = Date.now();
  const rec = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  attempts.set(ip, rec);
  return rec.length >= 8;
};
const recordFailure = (ip) => attempts.get(ip).push(Date.now());

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
  const pathname = url.pathname.replace(/\/+$/, '');
  const method = req.method;
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
  const secure = process.env.VERCEL || process.env.NODE_ENV === 'production' ? '; Secure' : '';

  if (pathname === '/api/session' && method === 'GET') return send(res, 200, { admin: isAdmin(req) });

  if (pathname === '/api/login' && method === 'POST') {
    if (!process.env.ADMIN_PASSWORD) return send(res, 500, { error: 'Server is missing the ADMIN_PASSWORD environment variable.' });
    if (rateLimited(ip)) return send(res, 429, { error: 'Too many attempts. Try again later.' });
    let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
    if (!passwordOk(body.password)) { recordFailure(ip); return send(res, 401, { error: 'Invalid passcode.' }); }
    return send(res, 200, { admin: true }, { 'Set-Cookie': `shek_session=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_S}${secure}` });
  }

  if (pathname === '/api/logout' && method === 'POST') {
    return send(res, 200, { admin: false }, { 'Set-Cookie': `shek_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}` });
  }

  if (pathname === '/api/posts' && method === 'GET') {
    const db = await getDb();
    const r = await db.execute('SELECT * FROM posts ORDER BY id DESC');
    return send(res, 200, r.rows.map(rowToPost));
  }

  const m = pathname.match(/^\/api\/posts\/(\d+)$/);
  if ((pathname === '/api/posts' && method === 'POST') || m) {
    if (!isAdmin(req)) return send(res, 401, { error: 'Admin login required.' });
    const origin = req.headers.origin;
    if (origin) { let host; try { host = new URL(origin).host; } catch { host = ''; } if (host !== req.headers.host) return send(res, 403, { error: 'Bad origin.' }); }
    const db = await getDb();

    if (!m && method === 'POST') {
      let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
      const { post, error } = validatePost(body);
      if (error) return send(res, 400, { error });
      const ins = await db.execute({ sql: 'INSERT INTO posts (title, author, status, description, file_link) VALUES (?,?,?,?,?)', args: [post.title, post.author, post.status, post.description, post.file_link] });
      const row = (await db.execute({ sql: 'SELECT * FROM posts WHERE id = ?', args: [Number(ins.lastInsertRowid)] })).rows[0];
      return send(res, 201, rowToPost(row));
    }
    if (m && method === 'PUT') {
      let body; try { body = await readJson(req); } catch { return send(res, 400, { error: 'Bad request.' }); }
      const { post, error } = validatePost(body);
      if (error) return send(res, 400, { error });
      const up = await db.execute({ sql: 'UPDATE posts SET title=?, author=?, status=?, description=?, file_link=? WHERE id=?', args: [post.title, post.author, post.status, post.description, post.file_link, Number(m[1])] });
      if (!up.rowsAffected) return send(res, 404, { error: 'Not found.' });
      const row = (await db.execute({ sql: 'SELECT * FROM posts WHERE id = ?', args: [Number(m[1])] })).rows[0];
      return send(res, 200, rowToPost(row));
    }
    if (m && method === 'DELETE') {
      const del = await db.execute({ sql: 'DELETE FROM posts WHERE id = ?', args: [Number(m[1])] });
      return send(res, del.rowsAffected ? 200 : 404, { ok: !!del.rowsAffected });
    }
  }
  return send(res, 404, { error: 'Not found.' });
}

module.exports = async function handler(req, res) {
  try { await handleApi(req, res); }
  catch (e) { console.error(e); send(res, 500, { error: 'Server error: ' + (e && e.message ? e.message : 'unknown') }); }
};
