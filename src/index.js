require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const { query } = require('./db');
const { signToken, auth, requireRole } = require('./auth');

if (!process.env.JWT_SECRET || !process.env.DATABASE_URL) {
  console.error('Missing JWT_SECRET or DATABASE_URL. Copy .env.example to .env and fill it in.');
  process.exit(1);
}

const TZ = process.env.APP_TZ || 'Asia/Kolkata';
const app = express();

app.use(helmet({ contentSecurityPolicy: false })); // admin page uses inline script/style
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// HR admin web page -> http://SERVER:4000/admin
app.use('/admin', express.static(path.join(__dirname, '..', 'public')));
app.get('/', (req, res) => res.redirect('/admin'));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

const hr = [auth, requireRole('hr')];
const employee = [auth, requireRole('employee')];

const DIRECTIONS = ['OUTGOING', 'INCOMING', 'MISSED', 'REJECTED'];
const normDirection = (d) => {
  const v = String(d || '').toUpperCase();
  return DIRECTIONS.includes(v) ? v : 'OTHER';
};
const isDate = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
const nullIfEmpty = (v) => (v === undefined || v === null || v === '' ? null : v);

/* ------------------------------ AUTH ------------------------------ */

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    const { rows } = await query('SELECT * FROM users WHERE username = $1', [username]);
    const user = rows[0];
    const ok = user && (await bcrypt.compare(password, user.password_hash));
    if (!ok) return res.status(401).json({ error: 'Wrong username or password' });
    if (!user.active) return res.status(403).json({ error: 'This account is disabled. Contact HR.' });

    res.json({
      token: signToken(user),
      user: { id: user.id, name: user.name, username: user.username, role: user.role },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

/* ------------------- EMPLOYEE: sync call logs from phone ------------------- */

app.get('/api/calls/last-sync', ...employee, async (req, res) => {
  try {
    const { rows } = await query('SELECT MAX(called_at) AS last FROM call_logs WHERE employee_id = $1', [req.user.id]);
    res.json({ lastCalledAt: rows[0].last ? new Date(rows[0].last).getTime() : 0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/calls/sync', ...employee, async (req, res) => {
  try {
    const calls = req.body.calls;
    if (!Array.isArray(calls)) return res.status(400).json({ error: 'calls must be an array' });
    if (calls.length === 0) return res.json({ received: 0, inserted: 0 });
    if (calls.length > 500) return res.status(400).json({ error: 'Send at most 500 calls per request' });

    const phones = [], names = [], dirs = [], durs = [], times = [];
    for (const c of calls) {
      const phone = String(c.phone_number || '').trim();
      const when = new Date(c.called_at);
      if (!phone || isNaN(when.getTime())) continue;
      phones.push(phone.slice(0, 40));
      names.push(c.contact_name ? String(c.contact_name).slice(0, 120) : null);
      dirs.push(normDirection(c.direction));
      durs.push(Math.max(0, Math.min(Number.parseInt(c.duration_sec, 10) || 0, 86400)));
      times.push(when.toISOString());
    }
    if (phones.length === 0) return res.json({ received: calls.length, inserted: 0 });

    const result = await query(
      `INSERT INTO call_logs (employee_id, phone_number, contact_name, direction, duration_sec, called_at)
       SELECT $1, p, n, d, s, t
       FROM unnest($2::text[], $3::text[], $4::text[], $5::int[], $6::timestamptz[]) AS x(p, n, d, s, t)
       ON CONFLICT (employee_id, phone_number, called_at) DO NOTHING`,
      [req.user.id, phones, names, dirs, durs, times]
    );
    res.json({ received: calls.length, inserted: result.rowCount });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Employee's own summary for today (shown in the mobile app)
app.get('/api/my/today', ...employee, async (req, res) => {
  try {
    const { rows } = await query(
      `SELECT COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE direction='OUTGOING')::int AS outgoing,
              COUNT(*) FILTER (WHERE direction='INCOMING')::int AS incoming,
              COUNT(*) FILTER (WHERE direction='MISSED')::int AS missed,
              COALESCE(SUM(duration_sec),0)::int AS talk_sec
       FROM call_logs
       WHERE employee_id = $1 AND (called_at AT TIME ZONE $2)::date = (now() AT TIME ZONE $2)::date`,
      [req.user.id, TZ]
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------------------ HR: call logs ------------------------------ */

const CALL_FILTER = `
  ($1::int  IS NULL OR c.employee_id = $1)
  AND ($2::text IS NULL OR c.direction = $2)
  AND ($3::date IS NULL OR (c.called_at AT TIME ZONE $6)::date >= $3::date)
  AND ($4::date IS NULL OR (c.called_at AT TIME ZONE $6)::date <= $4::date)
  AND ($5::text IS NULL OR c.phone_number ILIKE $5 OR c.contact_name ILIKE $5)`;

function callFilterParams(q) {
  const employeeId = Number.parseInt(q.employee_id, 10);
  const direction = String(q.direction || '').toUpperCase();
  const search = String(q.search || '').trim();
  return [
    Number.isInteger(employeeId) ? employeeId : null,
    DIRECTIONS.includes(direction) ? direction : null,
    isDate(q.from) ? q.from : null,
    isDate(q.to) ? q.to : null,
    search ? `%${search.replace(/[%_\\]/g, '\\$&')}%` : null,
    TZ,
  ];
}

app.get('/api/calls', ...hr, async (req, res) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const limit = Math.min(200, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
    const params = callFilterParams(req.query);

    const [list, count] = await Promise.all([
      query(
        `SELECT c.id, c.phone_number, c.contact_name, c.direction, c.duration_sec, c.called_at,
                c.summary, c.recording_url, u.id AS employee_id, u.name AS employee_name
         FROM call_logs c JOIN users u ON u.id = c.employee_id
         WHERE ${CALL_FILTER}
         ORDER BY c.called_at DESC
         LIMIT $7 OFFSET $8`,
        [...params, limit, (page - 1) * limit]
      ),
      query(
        `SELECT COUNT(*)::int AS total, COALESCE(SUM(c.duration_sec),0)::int AS talk_sec
         FROM call_logs c WHERE ${CALL_FILTER}`,
        params
      ),
    ]);

    res.json({
      calls: list.rows,
      page,
      limit,
      total: count.rows[0].total,
      talk_sec: count.rows[0].talk_sec,
      pages: Math.max(1, Math.ceil(count.rows[0].total / limit)),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

const PHONE_LIKE = /^\+?[\d\s()-]+$/;
const csvCell = (v) => {
  let s = v === null || v === undefined ? '' : String(v);
  // Stop spreadsheet formula injection from contact names, but leave real phone numbers (+91...) alone
  if (/^[=+\-@\t\r]/.test(s) && !PHONE_LIKE.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

app.get('/api/calls/export.csv', ...hr, async (req, res) => {
  try {
    const { rows } = await query(
      `SELECT u.name AS employee, c.phone_number, c.contact_name, c.direction, c.duration_sec,
              to_char(c.called_at AT TIME ZONE $6, 'YYYY-MM-DD HH24:MI:SS') AS called_at, c.summary
       FROM call_logs c JOIN users u ON u.id = c.employee_id
       WHERE ${CALL_FILTER}
       ORDER BY c.called_at DESC LIMIT 50000`,
      callFilterParams(req.query)
    );
    const header = ['Employee', 'Phone', 'Contact name', 'Direction', 'Duration (sec)', `Date/time (${TZ})`, 'Summary'];
    const lines = [header.join(',')].concat(
      rows.map((r) =>
        [r.employee, r.phone_number, r.contact_name, r.direction, r.duration_sec, r.called_at, r.summary].map(csvCell).join(',')
      )
    );
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="call-logs.csv"');
    res.send('﻿' + lines.join('\n'));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------------------ HR: stats ------------------------------ */

app.get('/api/stats', ...hr, async (req, res) => {
  try {
    const from = isDate(req.query.from) ? req.query.from : null;
    const to = isDate(req.query.to) ? req.query.to : null;
    const { rows } = await query(
      `SELECT u.id, u.name, u.username, u.active,
              COUNT(c.id)::int AS total,
              COUNT(c.id) FILTER (WHERE c.direction='OUTGOING')::int AS outgoing,
              COUNT(c.id) FILTER (WHERE c.direction='INCOMING')::int AS incoming,
              COUNT(c.id) FILTER (WHERE c.direction='MISSED')::int AS missed,
              COUNT(c.id) FILTER (WHERE c.direction IN ('OUTGOING','INCOMING') AND c.duration_sec > 0)::int AS connected,
              COALESCE(SUM(c.duration_sec),0)::int AS talk_sec,
              MAX(c.called_at) AS last_call
       FROM users u
       LEFT JOIN call_logs c ON c.employee_id = u.id
         AND ($1::date IS NULL OR (c.called_at AT TIME ZONE $3)::date >= $1::date)
         AND ($2::date IS NULL OR (c.called_at AT TIME ZONE $3)::date <= $2::date)
       WHERE u.role = 'employee'
       GROUP BY u.id
       ORDER BY u.name`,
      [from, to, TZ]
    );
    const totals = rows.reduce(
      (t, r) => ({
        total: t.total + r.total,
        outgoing: t.outgoing + r.outgoing,
        incoming: t.incoming + r.incoming,
        missed: t.missed + r.missed,
        talk_sec: t.talk_sec + r.talk_sec,
      }),
      { total: 0, outgoing: 0, incoming: 0, missed: 0, talk_sec: 0 }
    );
    res.json({ employees: rows, totals });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ------------------------------ HR: employees ------------------------------ */

app.get('/api/employees', ...hr, async (req, res) => {
  try {
    const { rows } = await query(
      `SELECT u.id, u.name, u.username, u.active, u.created_at,
              (SELECT MAX(created_at) FROM call_logs WHERE employee_id = u.id) AS last_sync
       FROM users u WHERE u.role = 'employee' ORDER BY u.name`
    );
    res.json({ employees: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/employees', ...hr, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!name || !username) return res.status(400).json({ error: 'Name and username are required' });
    if (!/^[a-z0-9._-]{3,40}$/.test(username))
      return res.status(400).json({ error: 'Username: 3-40 chars, letters, numbers, dot, dash, underscore' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const hash = await bcrypt.hash(password, 10);
    const { rows } = await query(
      `INSERT INTO users (name, username, password_hash, role) VALUES ($1, $2, $3, 'employee')
       RETURNING id, name, username, active, created_at`,
      [name, username, hash]
    );
    res.status(201).json({ employee: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'That username is already taken' });
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/employees/:id', ...hr, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Bad id' });

    const sets = [];
    const params = [];
    if (typeof req.body.active === 'boolean') {
      params.push(req.body.active);
      sets.push(`active = $${params.length}`);
    }
    if (nullIfEmpty(req.body.name)) {
      params.push(String(req.body.name).trim());
      sets.push(`name = $${params.length}`);
    }
    if (nullIfEmpty(req.body.password)) {
      if (String(req.body.password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      params.push(await bcrypt.hash(String(req.body.password), 10));
      sets.push(`password_hash = $${params.length}`);
    }
    if (!sets.length) return res.status(400).json({ error: 'Nothing to update' });

    params.push(id);
    const { rows } = await query(
      `UPDATE users SET ${sets.join(', ')} WHERE id = $${params.length} AND role = 'employee'
       RETURNING id, name, username, active`,
      params
    );
    if (!rows[0]) return res.status(404).json({ error: 'Employee not found' });
    res.json({ employee: rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Future: the summary pipeline (or HR) can attach a summary to a call
app.patch('/api/calls/:id/summary', ...hr, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Bad id' });
    const summary = String(req.body.summary || '').slice(0, 2000);
    const { rowCount } = await query('UPDATE call_logs SET summary = $1 WHERE id = $2', [summary, id]);
    if (!rowCount) return res.status(404).json({ error: 'Call not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.set('trust proxy', 1);

const port = Number(process.env.PORT) || 4000;
app.listen(port, () => console.log(`Call Tracker API running on port ${port}  ->  HR page: /admin`));
