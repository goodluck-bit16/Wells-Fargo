'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');

const scrypt = promisify(crypto.scrypt);

const CONFIG = {
  port: Number(process.env.PORT) || 3000,
  dbPath: process.env.DB_PATH || path.join(__dirname, 'larkspur.db'),
  cookieSecure: process.env.COOKIE_SECURE === '1',   // set to 1 when served over HTTPS
  trustProxy: process.env.TRUST_PROXY === '1',
  sessionSeconds: 60 * 60 * 8,
  maxCents: 100_000_000,                              // $1,000,000 per operation
  maxBody: 10 * 1024,
};

const TYPES = ['checking', 'savings'];
const PUBLIC_DIR = path.join(__dirname, 'public');
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
};

class HttpError extends Error {
  constructor(status, message, field) { super(message); this.status = status; this.field = field; }
}

/* ------------------------------------------------------------------ */
/* Database                                                           */
/* ------------------------------------------------------------------ */
function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT    NOT NULL,
      email      TEXT    NOT NULL UNIQUE,
      pw_salt    BLOB    NOT NULL,
      pw_hash    BLOB    NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS accounts (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       INTEGER NOT NULL REFERENCES users(id),
      type          TEXT    NOT NULL CHECK (type IN ('checking','savings')),
      number        TEXT    NOT NULL UNIQUE,
      balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0),
      UNIQUE (user_id, type)
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id      INTEGER NOT NULL REFERENCES users(id),
      account_id   INTEGER NOT NULL REFERENCES accounts(id),
      description  TEXT    NOT NULL,
      amount_cents INTEGER NOT NULL,
      created_at   INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(user_id, id DESC);
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id),
      expires_at INTEGER NOT NULL
    );
  `);
  return db;
}

/** All-or-nothing: either every statement in fn() is saved or none are. */
function atomic(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
}

const now = () => Math.floor(Date.now() / 1000);

/* ------------------------------------------------------------------ */
/* Validation helpers                                                 */
/* ------------------------------------------------------------------ */
function str(v, field, min, max, label) {
  if (typeof v !== 'string') throw new HttpError(400, `Enter ${label}.`, field);
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (s.length < min) throw new HttpError(400, `Enter ${label}.`, field);
  if (s.length > max) throw new HttpError(400, `${label[0].toUpperCase() + label.slice(1)} is too long (max ${max} characters).`, field);
  return s;
}

function toCents(v, field, { allowZero = false } = {}) {
  const n = typeof v === 'number' ? v : (typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN);
  if (!Number.isFinite(n)) throw new HttpError(400, 'Enter an amount in dollars, like 25.00.', field);
  const cents = Math.round(n * 100);
  if (Math.abs(n * 100 - cents) > 1e-6) throw new HttpError(400, 'Use at most two decimal places.', field);
  if (cents < 0 || (!allowZero && cents === 0)) throw new HttpError(400, allowZero ? 'Enter $0 or more.' : 'Enter an amount greater than $0.', field);
  if (cents > CONFIG.maxCents) throw new HttpError(400, 'That amount is above the $1,000,000 limit.', field);
  return cents;
}

function acctType(v, field) {
  if (!TYPES.includes(v)) throw new HttpError(400, 'Choose checking or savings.', field);
  return v;
}

const money = c => '$' + (c / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const cap = s => s[0].toUpperCase() + s.slice(1);

/* ------------------------------------------------------------------ */
/* Passwords & sessions                                               */
/* ------------------------------------------------------------------ */
async function hashPassword(pw, salt) { return scrypt(pw, salt, 64); }
const DUMMY_SALT = crypto.randomBytes(16);

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

function createSession(db, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now());
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)')
    .run(sha256(token), userId, now() + CONFIG.sessionSeconds);
  return token;
}

function cookieHeader(token, maxAge) {
  return `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}` + (CONFIG.cookieSecure ? '; Secure' : '');
}

function parseCookies(h = '') {
  const out = {};
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function sessionUser(db, req) {
  const token = parseCookies(req.headers.cookie).sid;
  if (!token) return null;
  const row = db.prepare('SELECT user_id FROM sessions WHERE token_hash = ? AND expires_at > ?').get(sha256(token), now());
  return row ? row.user_id : null;
}

function requireUser(db, req) {
  const id = sessionUser(db, req);
  if (!id) throw new HttpError(401, 'Sign in to continue.');
  return id;
}

/* ------------------------------------------------------------------ */
/* Rate limiting (in memory, per process)                             */
/* ------------------------------------------------------------------ */
function makeLimiter() {
  const hits = new Map();
  return function hit(key, max, windowMs) {
    const t = Date.now();
    const e = hits.get(key);
    if (!e || e.reset < t) { hits.set(key, { n: 1, reset: t + windowMs }); }
    else if (++e.n > max) { throw new HttpError(429, 'Too many attempts. Wait a few minutes and try again.'); }
    if (hits.size > 5000) for (const [k, v] of hits) if (v.reset < t) hits.delete(k);
  };
}

/* ------------------------------------------------------------------ */
/* App                                                                */
/* ------------------------------------------------------------------ */
function createApp(dbPath = CONFIG.dbPath) {
  const db = openDb(dbPath);
  const limit = makeLimiter();

  function snapshot(userId) {
    const user = db.prepare('SELECT name, email FROM users WHERE id = ?').get(userId);
    const accounts = {};
    for (const a of db.prepare('SELECT type, number, balance_cents FROM accounts WHERE user_id = ?').all(userId)) {
      accounts[a.type] = { last4: a.number.slice(-4), balanceCents: a.balance_cents };
    }
    const transactions = db.prepare(`
      SELECT t.id, t.description, t.amount_cents AS amountCents, t.created_at AS createdAt, a.type AS account
      FROM transactions t JOIN accounts a ON a.id = t.account_id
      WHERE t.user_id = ? ORDER BY t.id DESC LIMIT 25`).all(userId);
    return { user: { name: user.name, email: user.email }, accounts, transactions };
  }

  const getAcct = (userId, type) =>
    db.prepare('SELECT id, balance_cents FROM accounts WHERE user_id = ? AND type = ?').get(userId, type);

  const addTx = (userId, accountId, description, cents) =>
    db.prepare('INSERT INTO transactions (user_id, account_id, description, amount_cents, created_at) VALUES (?,?,?,?,?)')
      .run(userId, accountId, description, cents, now());

  function newAccountNumber(userId, type, cents) {
    for (let i = 0; i < 10; i++) {
      const number = Array.from({ length: 10 }, () => crypto.randomInt(10)).join('');
      try {
        const r = db.prepare('INSERT INTO accounts (user_id, type, number, balance_cents) VALUES (?,?,?,?)').run(userId, type, number, cents);
        return Number(r.lastInsertRowid);
      } catch (e) { if (!/UNIQUE.*accounts\.number/.test(String(e.message))) throw e; }
    }
    throw new Error('Could not allocate an account number');
  }

  /* ---------- handlers: each returns { status?, body, cookie? } ---------- */
  const routes = {
    async 'POST /api/register'(req, b, ctx) {
      limit(`reg|${ctx.ip}`, 10, 60 * 60 * 1000);
      const name = str(b.name, 'name', 2, 80, 'your full name');
      const email = str(b.email, 'email', 3, 254, 'your email').toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'Enter an email like name@example.com.', 'email');
      if (typeof b.password !== 'string' || b.password.length < 8) throw new HttpError(400, 'Use at least 8 characters.', 'password');
      if (b.password.length > 128) throw new HttpError(400, 'Use 128 characters or fewer.', 'password');
      const type = acctType(b.type, 'type');
      const deposit = toCents(b.deposit ?? 0, 'deposit', { allowZero: true });

      if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) {
        throw new HttpError(409, 'An account with this email already exists. Sign in instead.', 'email');
      }
      const salt = crypto.randomBytes(16);
      const hash = await hashPassword(b.password, salt);

      const userId = atomic(db, () => {
        let id;
        try {
          id = Number(db.prepare('INSERT INTO users (name,email,pw_salt,pw_hash,created_at) VALUES (?,?,?,?,?)')
            .run(name, email, salt, hash, now()).lastInsertRowid);
        } catch (e) {
          if (/UNIQUE.*users\.email/.test(String(e.message))) throw new HttpError(409, 'An account with this email already exists. Sign in instead.', 'email');
          throw e;
        }
        for (const t of TYPES) {
          const accId = newAccountNumber(id, t, t === type ? deposit : 0);
          if (t === type && deposit > 0) addTx(id, accId, `Opening deposit to ${cap(t)}`, deposit);
        }
        return id;
      });
      const token = createSession(db, userId);
      return { status: 201, body: snapshot(userId), cookie: cookieHeader(token, CONFIG.sessionSeconds) };
    },

    async 'POST /api/login'(req, b, ctx) {
      const email = typeof b.email === 'string' ? b.email.trim().toLowerCase().slice(0, 254) : '';
      const pw = typeof b.password === 'string' ? b.password.slice(0, 128) : '';
      limit(`login|${ctx.ip}|${email}`, 5, 15 * 60 * 1000);
      limit(`login-ip|${ctx.ip}`, 40, 15 * 60 * 1000);
      const user = db.prepare('SELECT id, pw_salt, pw_hash FROM users WHERE email = ?').get(email);
      // Always run scrypt so response time doesn't reveal whether the email exists.
      const calc = await hashPassword(pw, user ? Buffer.from(user.pw_salt) : DUMMY_SALT);
      const ok = user && crypto.timingSafeEqual(calc, Buffer.from(user.pw_hash));
      if (!ok) throw new HttpError(401, 'Email or password is incorrect.');
      const token = createSession(db, user.id);
      return { body: snapshot(user.id), cookie: cookieHeader(token, CONFIG.sessionSeconds) };
    },

    'POST /api/logout'(req) {
      const token = parseCookies(req.headers.cookie).sid;
      if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
      return { body: { ok: true }, cookie: cookieHeader('', 0) };
    },

    'GET /api/me'(req) {
      return { body: snapshot(requireUser(db, req)) };
    },

    'POST /api/deposit'(req, b) {
      const userId = requireUser(db, req);
      const type = acctType(b.account, 'account');
      const cents = toCents(b.amount, 'amount');
      atomic(db, () => {
        const a = getAcct(userId, type);
        db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?').run(cents, a.id);
        addTx(userId, a.id, `Deposit to ${cap(type)}`, cents);
      });
      return { body: { ...snapshot(userId), message: `Deposited ${money(cents)}` } };
    },

    'POST /api/transfer'(req, b) {
      const userId = requireUser(db, req);
      const from = acctType(b.from, 'from');
      const to = acctType(b.to, 'to');
      if (from === to) throw new HttpError(400, 'Choose two different accounts.', 'to');
      const cents = toCents(b.amount, 'amount');
      atomic(db, () => {
        const a = getAcct(userId, from), z = getAcct(userId, to);
        if (a.balance_cents < cents) throw new HttpError(400, `${cap(from)} has ${money(a.balance_cents)}. Enter a smaller amount.`, 'amount');
        db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?').run(cents, a.id);
        db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?').run(cents, z.id);
        addTx(userId, a.id, `Transfer to ${cap(to)}`, -cents);
        addTx(userId, z.id, `Transfer from ${cap(from)}`, cents);
      });
      return { body: { ...snapshot(userId), message: `Transferred ${money(cents)}` } };
    },

    'POST /api/send'(req, b) {
      const userId = requireUser(db, req);
      const from = acctType(b.from, 'from');
      const payee = str(b.payee, 'payee', 1, 80, 'who you are sending money to');
      const cents = toCents(b.amount, 'amount');
      atomic(db, () => {
        const a = getAcct(userId, from);
        if (a.balance_cents < cents) throw new HttpError(400, `${cap(from)} has ${money(a.balance_cents)}. Enter a smaller amount.`, 'amount');
        db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?').run(cents, a.id);
        addTx(userId, a.id, `Sent to ${payee}`, -cents);
      });
      return { body: { ...snapshot(userId), message: `Sent ${money(cents)} to ${payee}` } };
    },
  };

  /* ---------- HTTP plumbing ---------- */
  function securityHeaders(res) {
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; " +
      "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; " +
      "frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      let size = 0; const chunks = [];
      req.on('data', c => {
        size += c.length;
        if (size > CONFIG.maxBody) { reject(new HttpError(413, 'Request is too large.')); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => {
        try {
          const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
          if (!v || typeof v !== 'object' || Array.isArray(v)) throw 0;
          resolve(v);
        } catch { reject(new HttpError(400, 'Request body must be a JSON object.')); }
      });
      req.on('error', reject);
    });
  }

  function send(res, status, body, headers = {}) {
    const data = JSON.stringify(body);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
    res.end(data);
  }

  const server = http.createServer(async (req, res) => {
    securityHeaders(res);
    try {
      const url = new URL(req.url, 'http://localhost');

      if (url.pathname.startsWith('/api/')) {
        const handler = routes[`${req.method} ${url.pathname}`];
        if (!handler) throw new HttpError(404, 'Not found.');
        let body = {};
        if (req.method === 'POST') {
          // CSRF defenses: SameSite=Strict cookie + JSON-only + same-origin check.
          if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Send JSON.');
          const origin = req.headers.origin;
          if (origin && new URL(origin).host !== req.headers.host) throw new HttpError(403, 'Cross-site requests are not allowed.');
          body = await readJson(req);
        }
        const ip = (CONFIG.trustProxy && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
        const out = await handler(req, body, { ip });
        return send(res, out.status || 200, out.body, out.cookie ? { 'Set-Cookie': out.cookie } : {});
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed.');
      const file = STATIC[url.pathname];
      if (!file) throw new HttpError(404, 'Not found.');
      const content = fs.readFileSync(path.join(PUBLIC_DIR, file[0]));
      res.writeHead(200, { 'Content-Type': file[1], 'Cache-Control': 'no-cache' });
      res.end(req.method === 'HEAD' ? undefined : content);
    } catch (e) {
      if (e instanceof HttpError) {
        const wantsJson = (req.url || '').startsWith('/api/');
        if (wantsJson) return send(res, e.status, { error: e.message, field: e.field });
        res.writeHead(e.status, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end(e.message);
      }
      console.error(e);
      send(res, 500, { error: 'Something went wrong on our side. Try again.' });
    }
  });

  return { server, db };
}

module.exports = { createApp, CONFIG };

if (require.main === module) {
  const { server, db } = createApp();
  server.listen(CONFIG.port, () => console.log(`Larkspur Bank running at http://localhost:${CONFIG.port}`));
  const stop = () => { server.close(); db.close(); process.exit(0); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
