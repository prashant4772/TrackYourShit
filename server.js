const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tracl-dev-secret-change-in-production';

// ── DATABASE SETUP ──
const db = new Database(path.join(__dirname, 'tracl.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    pass_hash   TEXT NOT NULL,
    goal_secs   INTEGER NOT NULL DEFAULT 18000,
    created_at  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id),
    started_at    INTEGER NOT NULL,
    ended_at      INTEGER,
    duration_secs INTEGER,
    method        TEXT DEFAULT 'manual',
    note          TEXT,
    created_at    INTEGER NOT NULL
  );
`);

// ── MIDDLEWARE ──
app.use(express.json());

// CORS — allow all origins for development, tighten in production
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Serve the frontend from /public
const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) app.use(express.static(publicDir));

// ── HELPERS ──
function hashPass(pass) {
  return crypto.createHash('sha256').update(pass + JWT_SECRET).digest('hex');
}

function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '90d' });
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'not authenticated' });
  try {
    const { userId } = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = userId;
    next();
  } catch {
    res.status(401).json({ error: 'token expired or invalid' });
  }
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// ── AUTH ROUTES ──

// POST /auth/signup
app.post('/auth/signup', (req, res) => {
  const { name, email, password, goalSecs } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'password must be at least 6 characters' });
  if (!email.includes('@')) return res.status(400).json({ error: 'invalid email' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'email already in use' });

  const user = {
    id: uid(),
    name: name.trim(),
    email: email.toLowerCase().trim(),
    pass_hash: hashPass(password),
    goal_secs: goalSecs || 18000,
    created_at: Date.now()
  };

  db.prepare('INSERT INTO users (id, name, email, pass_hash, goal_secs, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(user.id, user.name, user.email, user.pass_hash, user.goal_secs, user.created_at);

  res.json({ token: makeToken(user.id), user: { id: user.id, name: user.name, email: user.email, goalSecs: user.goal_secs } });
});

// POST /auth/login
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user || user.pass_hash !== hashPass(password)) return res.status(401).json({ error: 'incorrect email or password' });

  res.json({ token: makeToken(user.id), user: { id: user.id, name: user.name, email: user.email, goalSecs: user.goal_secs } });
});

// GET /auth/me — validate token and return user
app.get('/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, goal_secs FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });
  res.json({ id: user.id, name: user.name, email: user.email, goalSecs: user.goal_secs });
});

// ── SESSION ROUTES ──

// POST /sessions/start — records server-side start timestamp
app.post('/sessions/start', requireAuth, (req, res) => {
  const { method } = req.body;
  const now = Date.now();

  // Check for already-open session
  const open = db.prepare('SELECT id FROM sessions WHERE user_id = ? AND ended_at IS NULL').get(req.userId);
  if (open) return res.status(409).json({ error: 'session already active', sessionId: open.id });

  const session = {
    id: uid(),
    user_id: req.userId,
    started_at: now,
    method: method || 'manual',
    created_at: now
  };

  db.prepare('INSERT INTO sessions (id, user_id, started_at, method, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(session.id, session.user_id, session.started_at, session.method, session.created_at);

  // Return the authoritative server timestamp
  res.json({ sessionId: session.id, startedAt: session.started_at });
});

// POST /sessions/end — closes the session
app.post('/sessions/end', requireAuth, (req, res) => {
  const { sessionId, note } = req.body;
  const now = Date.now();

  const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND user_id = ?').get(sessionId, req.userId);
  if (!session) return res.status(404).json({ error: 'session not found' });
  if (session.ended_at) return res.status(409).json({ error: 'session already ended' });

  const durationSecs = Math.floor((now - session.started_at) / 1000);

  // Discard accidental taps under 30 seconds
  if (durationSecs < 30) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(sessionId);
    return res.json({ discarded: true, reason: 'session too short' });
  }

  db.prepare('UPDATE sessions SET ended_at = ?, duration_secs = ?, note = ? WHERE id = ?')
    .run(now, durationSecs, note || null, sessionId);

  res.json({
    sessionId,
    startedAt: session.started_at,
    endedAt: now,
    durationSecs
  });
});

// GET /sessions/today — all of today's sessions
app.get('/sessions/today', requireAuth, (req, res) => {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);

  const sessions = db.prepare(`
    SELECT id, started_at, ended_at, duration_secs, method, note
    FROM sessions
    WHERE user_id = ? AND started_at >= ? AND ended_at IS NOT NULL
    ORDER BY started_at DESC
  `).all(req.userId, startOfDay.getTime());

  // Also check for an open session
  const open = db.prepare('SELECT id, started_at, method FROM sessions WHERE user_id = ? AND ended_at IS NULL').get(req.userId);

  res.json({ sessions, activeSession: open || null });
});

// GET /sessions/week — last 7 days of sessions
app.get('/sessions/week', requireAuth, (req, res) => {
  const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;

  const sessions = db.prepare(`
    SELECT id, started_at, ended_at, duration_secs, method
    FROM sessions
    WHERE user_id = ? AND started_at >= ? AND ended_at IS NOT NULL
    ORDER BY started_at DESC
  `).all(req.userId, sevenDaysAgo);

  res.json({ sessions });
});

// GET /sessions/stats — streak, weekly total, avg session
app.get('/sessions/stats', requireAuth, (req, res) => {
  const allSessions = db.prepare(`
    SELECT started_at, duration_secs
    FROM sessions
    WHERE user_id = ? AND ended_at IS NOT NULL
    ORDER BY started_at DESC
  `).all(req.userId);

  // Streak
  let streak = 0;
  const seen = new Set(allSessions.map(s => new Date(s.started_at).toISOString().slice(0,10)));
  for (let i = 0; i < 365; i++) {
    const d = new Date(); d.setDate(d.getDate() - i);
    if (seen.has(d.toISOString().slice(0,10))) streak++;
    else if (i > 0) break;
  }

  // Week total
  const sevenAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const weekTotal = allSessions.filter(s => s.started_at >= sevenAgo).reduce((a, s) => a + s.duration_secs, 0);

  // Avg session
  const avg = allSessions.length > 0
    ? Math.round(allSessions.reduce((a, s) => a + s.duration_secs, 0) / allSessions.length)
    : 0;

  res.json({ streak, weekTotal, avgSession: avg, totalSessions: allSessions.length });
});

// ── HEALTH CHECK ──
app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));

// ── START ──
app.listen(PORT, () => {
  console.log(`tracl backend running on http://localhost:${PORT}`);
});
