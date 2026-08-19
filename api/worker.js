// Copilot Check-in API — Cloudflare Worker + D1
// Routes (all under /api):
//   POST   /api/register      {username, password}        -> {token, username}
//   POST   /api/login         {username, password}        -> {token, username}
//   POST   /api/logout        (Bearer)                    -> {ok}
//   GET    /api/me            (Bearer)                    -> {username}
//   GET    /api/records       (Bearer)                    -> {records: {date: {app, web, env, ts}}}
//   PUT    /api/records       (Bearer) {date,app,web,env} -> {ok}
//   POST   /api/records/batch (Bearer) {records:{...}}    -> {ok, count}
//   DELETE /api/records/:date (Bearer)                    -> {ok}

const SESSION_TTL_MS = 30 * 24 * 3600 * 1000; // 30 days
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
}

function isValidUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_\u4e00-\u9fa5-]{2,20}$/.test(u);
}

function validRecord(rec) {
  return rec && (rec.app === 'yes' || rec.app === 'no') &&
         (rec.web === 'yes' || rec.web === 'no') &&
         typeof rec.env === 'string' && rec.env.length > 0 && rec.env.length <= 10 &&
         typeof rec.date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(rec.date);
}

async function authUser(request, env) {
  const header = request.headers.get('Authorization') || '';
  const match = header.match(/^Bearer\s+([a-f0-9]{64})$/i);
  if (!match) return null;
  const token = match[1];
  const row = await env.DB.prepare(
    'SELECT s.token, s.expires_at, u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?'
  ).bind(token).first();
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return { id: row.id, username: row.username, token };
}

async function createSession(env, userId) {
  const token = randomHex(32);
  const now = Date.now();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(token, userId, now, now + SESSION_TTL_MS).run();
  return token;
}

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid body' }, 400); }
  const username = (body.username || '').trim();
  const password = body.password || '';
  if (!isValidUsername(username)) return json({ error: '用户名需 2-20 个字符（字母、数字、下划线、中文）' }, 400);
  if (typeof password !== 'string' || password.length < 4) return json({ error: '密码至少 4 位' }, 400);

  const exists = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username.toLowerCase()).first();
  if (exists) return json({ error: '用户名已存在，请直接登录' }, 409);

  const salt = randomHex(16);
  const hash = await sha256Hex(salt + password);
  const result = await env.DB.prepare('INSERT INTO users (username, salt, hash, created_at) VALUES (?, ?, ?, ?)')
    .bind(username.toLowerCase(), salt, hash, Date.now()).run();
  const userId = result.meta.last_row_id;
  const token = await createSession(env, userId);
  return json({ token, username }, 201);
}

async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid body' }, 400); }
  const username = (body.username || '').trim().toLowerCase();
  const password = body.password || '';
  const user = await env.DB.prepare('SELECT id, username, salt, hash FROM users WHERE username = ?').bind(username).first();
  if (!user) return json({ error: '用户不存在，请先注册' }, 404);
  const hash = await sha256Hex(user.salt + password);
  if (hash !== user.hash) return json({ error: '密码错误' }, 401);
  const token = await createSession(env, user.id);
  return json({ token, username: user.username });
}

async function handleGetRecords(user, env) {
  const { results } = await env.DB.prepare('SELECT date, app, web, env, ts FROM checkins WHERE user_id = ?').bind(user.id).all();
  const records = {};
  for (const row of results) {
    records[row.date] = { app: row.app, web: row.web, env: row.env, ts: row.ts };
  }
  return json({ records });
}

async function handlePutRecord(user, request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid body' }, 400); }
  const rec = { date: body.date, app: body.app, web: body.web, env: body.env };
  if (!validRecord(rec)) return json({ error: 'invalid record' }, 400);
  await env.DB.prepare(
    'INSERT INTO checkins (user_id, date, app, web, env, ts) VALUES (?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT (user_id, date) DO UPDATE SET app = excluded.app, web = excluded.web, env = excluded.env, ts = excluded.ts'
  ).bind(user.id, rec.date, rec.app, rec.web, rec.env, Date.now()).run();
  return json({ ok: true });
}

async function handleBatchRecords(user, request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'invalid body' }, 400); }
  const incoming = body.records || {};
  const stmts = [];
  for (const [date, rec] of Object.entries(incoming)) {
    const r = { date, app: rec.app, web: rec.web, env: rec.env };
    if (!validRecord(r)) continue;
    stmts.push(
      env.DB.prepare(
        'INSERT INTO checkins (user_id, date, app, web, env, ts) VALUES (?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT (user_id, date) DO UPDATE SET app = excluded.app, web = excluded.web, env = excluded.env, ts = excluded.ts'
      ).bind(user.id, r.date, r.app, r.web, r.env, rec.ts || Date.now())
    );
  }
  if (stmts.length) await env.DB.batch(stmts);
  return json({ ok: true, count: stmts.length });
}

async function handleDeleteRecord(user, dateStr, env) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return json({ error: 'invalid date' }, 400);
  await env.DB.prepare('DELETE FROM checkins WHERE user_id = ? AND date = ?').bind(user.id, dateStr).run();
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      if (path === '/api/register' && request.method === 'POST') return await handleRegister(request, env);
      if (path === '/api/login' && request.method === 'POST') return await handleLogin(request, env);

      const user = await authUser(request, env);
      if (!user) return json({ error: '未登录或会话已过期' }, 401);

      if (path === '/api/logout' && request.method === 'POST') {
        await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(user.token).run();
        return json({ ok: true });
      }
      if (path === '/api/me' && request.method === 'GET') return json({ username: user.username });
      if (path === '/api/records' && request.method === 'GET') return await handleGetRecords(user, env);
      if (path === '/api/records' && request.method === 'PUT') return await handlePutRecord(user, request, env);
      if (path === '/api/records/batch' && request.method === 'POST') return await handleBatchRecords(user, request, env);
      const delMatch = path.match(/^\/api\/records\/(\d{4}-\d{2}-\d{2})$/);
      if (delMatch && request.method === 'DELETE') return await handleDeleteRecord(user, delMatch[1], env);

      return json({ error: 'not found' }, 404);
    } catch (err) {
      return json({ error: 'server error: ' + (err && err.message) }, 500);
    }
  },
};
