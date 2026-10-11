'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('./server');

let base, server, db;
test.before(async () => {
  ({ server, db } = createApp(':memory:'));
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => { server.close(); db.close(); });

function client() {
  let cookie = '';
  return async (path, method = 'GET', body, headers = {}) => {
    const res = await fetch(base + path, {
      method,
      headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
    });
    const sc = res.headers.get('set-cookie');
    if (sc) cookie = sc.split(';')[0].endsWith('=') ? '' : sc.split(';')[0];
    return { status: res.status, json: await res.json().catch(() => ({})), res };
  };
}
const reg = (over = {}) => ({ name: 'Ada Lovelace', email: 'ada@example.com', password: 'correct horse', type: 'checking', deposit: 100, ...over });

test('serves the site and security headers', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  assert.match(await res.text(), /How it works/);
  assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal((await fetch(base + '/server.js')).status, 404);
});

test('register opens both accounts, funds the chosen one, sets an HttpOnly session', async () => {
  const c = client();
  const r = await c('/api/register', 'POST', reg());
  assert.equal(r.status, 201);
  assert.equal(r.json.accounts.checking.balanceCents, 10000);
  assert.equal(r.json.accounts.savings.balanceCents, 0);
  assert.equal(r.json.transactions.length, 1);
  const sc = r.res.headers.get('set-cookie');
  assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/);
  assert.equal((await c('/api/me')).status, 200);
});

test('passwords are hashed, never stored in plain text', () => {
  const row = db.prepare('SELECT pw_hash FROM users WHERE email = ?').get('ada@example.com');
  assert.ok(!Buffer.from(row.pw_hash).toString('utf8').includes('correct horse'));
});

test('duplicate email and bad input are rejected with field names', async () => {
  const c = client();
  assert.equal((await c('/api/register', 'POST', reg({ email: 'ADA@example.com' }))).json.field, 'email');
  assert.equal((await c('/api/register', 'POST', reg({ email: 'bad', name: 'Bo' }))).json.field, 'email');
  assert.equal((await c('/api/register', 'POST', reg({ email: 'x@y.co', password: 'short' }))).json.field, 'password');
  assert.equal((await c('/api/register', 'POST', reg({ email: 'x@y.co', deposit: -5 }))).json.field, 'deposit');
  assert.equal((await c('/api/register', 'POST', reg({ email: 'x@y.co', deposit: 1.234 }))).json.field, 'deposit');
});

test('login works, wrong password fails, logout ends the session', async () => {
  const c = client();
  assert.equal((await c('/api/login', 'POST', { email: 'ada@example.com', password: 'nope nope' })).status, 401);
  assert.equal((await c('/api/login', 'POST', { email: 'nobody@example.com', password: 'whatever1' })).status, 401);
  assert.equal((await c('/api/login', 'POST', { email: 'Ada@Example.com', password: 'correct horse' })).status, 200);
  assert.equal((await c('/api/me')).status, 200);
  await c('/api/logout', 'POST', {});
  assert.equal((await c('/api/me')).status, 401);
});

test('login is rate limited after repeated failures', async () => {
  const c = client(); let last;
  for (let i = 0; i < 7; i++) last = await c('/api/login', 'POST', { email: 'victim@example.com', password: 'guess' + i });
  assert.equal(last.status, 429);
});

test('money endpoints need a session', async () => {
  const c = client();
  assert.equal((await c('/api/deposit', 'POST', { account: 'checking', amount: 5 })).status, 401);
});

test('deposit, transfer and send keep exact balances', async () => {
  const c = client();
  await c('/api/register', 'POST', reg({ email: 'grace@example.com', name: 'Grace Hopper', deposit: 0 }));
  let r = await c('/api/deposit', 'POST', { account: 'checking', amount: 0.1 });
  r = await c('/api/deposit', 'POST', { account: 'checking', amount: 0.2 });
  assert.equal(r.json.accounts.checking.balanceCents, 30);           // no 0.30000000000000004
  r = await c('/api/deposit', 'POST', { account: 'checking', amount: 100 });
  r = await c('/api/transfer', 'POST', { from: 'checking', to: 'savings', amount: 40.25 });
  assert.equal(r.json.accounts.checking.balanceCents, 6000 + 5 );    // 100.30 - 40.25 = 60.05
  assert.equal(r.json.accounts.savings.balanceCents, 4025);
  r = await c('/api/send', 'POST', { from: 'savings', payee: 'Corner Cafe', amount: 5 });
  assert.equal(r.json.accounts.savings.balanceCents, 3525);
  assert.equal(r.json.transactions[0].description, 'Sent to Corner Cafe');
});

test('overdrafts and nonsense amounts are blocked and change nothing', async () => {
  const c = client();
  await c('/api/register', 'POST', reg({ email: 'alan@example.com', name: 'Alan Turing', deposit: 50 }));
  const before = (await c('/api/me')).json;
  for (const [path, body] of [
    ['/api/transfer', { from: 'checking', to: 'savings', amount: 50.01 }],
    ['/api/send', { from: 'checking', payee: 'X', amount: 999 }],
    ['/api/transfer', { from: 'checking', to: 'checking', amount: 1 }],
    ['/api/deposit', { account: 'checking', amount: -1 }],
    ['/api/deposit', { account: 'checking', amount: 'abc' }],
    ['/api/deposit', { account: 'checking', amount: 2e9 }],
    ['/api/deposit', { account: 'bogus', amount: 1 }],
  ]) assert.equal((await c(path, 'POST', body)).status, 400, path + JSON.stringify(body));
  const after = (await c('/api/me')).json;
  assert.deepEqual(after.accounts, before.accounts);
  assert.equal(after.transactions.length, before.transactions.length);
});

test("users can't see each other's data", async () => {
  const a = client(), b = client();
  await a('/api/register', 'POST', reg({ email: 'a1@example.com', name: 'User A', deposit: 10 }));
  await b('/api/register', 'POST', reg({ email: 'b1@example.com', name: 'User B', deposit: 20 }));
  assert.equal((await a('/api/me')).json.accounts.checking.balanceCents, 1000);
  assert.equal((await b('/api/me')).json.accounts.checking.balanceCents, 2000);
});

test('CSRF guards: JSON only and same-origin only', async () => {
  const c = client();
  await c('/api/register', 'POST', reg({ email: 'csrf@example.com', name: 'Csrf Test' }));
  const form = await fetch(base + '/api/deposit', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'x=1' });
  assert.equal(form.status, 415);
  const cross = await c('/api/deposit', 'POST', { account: 'checking', amount: 1 }, { Origin: 'https://evil.example' });
  assert.equal(cross.status, 403);
});
