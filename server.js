const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tracl-dev-secret-change-in-production';
const DB_PATH = process.env.DATA_PATH || path.join(__dirname, 'tracl.db.json');

// ── DATABASE ──
function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {}
  return { users: [], sessions: [] };
}
function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db), 'utf8');
}
const q = {
  userByEmail: (db, email) => db.users.find(u => u.email === email),
  userById: (db, id) => db.users.find(u => u.id === id),
  sessionsByUser: (db, userId) => db.sessions.filter(s => s.userId === userId),
  openSession: (db, userId) => db.sessions.find(s => s.userId === userId && !s.endedAt),
  sessionById: (db, id, userId) => db.sessions.find(s => s.id === id && s.userId === userId),
};

// ── SSE: per-user connected clients ──
const clients = new Map(); // userId -> Set of res objects

function getClients(userId) {
  if (!clients.has(userId)) clients.set(userId, new Set());
  return clients.get(userId);
}

function pushToUser(userId, event, data) {
  const conns = clients.get(userId);
  if (!conns) return;
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of conns) {
    try { res.write(msg); } catch {}
  }
}

// ── MIDDLEWARE ──
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ── HELPERS ──
function hashPass(pass) {
  return crypto.createHash('sha256').update(pass + JWT_SECRET).digest('hex');
}
function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '90d' });
}
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'not authenticated' });
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
function dayKey(ts) {
  return new Date(ts).toISOString().slice(0, 10);
}

// ── SSE ENDPOINT ──
// EventSource can't send headers, so we accept token via query param too
app.get('/events', (req, res) => {
  const token = req.headers.authorization?.slice(7) || req.query.token;
  if (!token) return res.status(401).end();
  try {
    const { userId } = jwt.verify(token, JWT_SECRET);
    req.userId = userId;
  } catch { return res.status(401).end(); }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Send a heartbeat every 25s to keep the connection alive through proxies
  const heartbeat = setInterval(() => {
    try { res.write(': ping\n\n'); } catch {}
  }, 25000);

  const userClients = getClients(req.userId);
  userClients.add(res);

  req.on('close', () => {
    clearInterval(heartbeat);
    userClients.delete(res);
  });
});

// ── AUTH ──
app.post('/auth/signup', (req, res) => {
  const { name, email, password, goalSecs } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'password must be at least 6 characters' });
  if (!email.includes('@')) return res.status(400).json({ error: 'invalid email' });

  const db = loadDB();
  if (q.userByEmail(db, email.toLowerCase())) return res.status(409).json({ error: 'email already in use' });

  const user = {
    id: uid(),
    name: name.trim(),
    email: email.toLowerCase().trim(),
    passHash: hashPass(password),
    goalSecs: goalSecs || 18000,
    createdAt: Date.now()
  };
  db.users.push(user);
  saveDB(db);

  res.json({ token: makeToken(user.id), user: { id: user.id, name: user.name, email: user.email, goalSecs: user.goalSecs } });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const db = loadDB();
  const user = q.userByEmail(db, email.toLowerCase().trim());
  if (!user || user.passHash !== hashPass(password)) return res.status(401).json({ error: 'incorrect email or password' });

  res.json({ token: makeToken(user.id), user: { id: user.id, name: user.name, email: user.email, goalSecs: user.goalSecs } });
});

app.get('/auth/me', requireAuth, (req, res) => {
  const db = loadDB();
  const user = q.userById(db, req.userId);
  if (!user) return res.status(404).json({ error: 'user not found' });
  res.json({ id: user.id, name: user.name, email: user.email, goalSecs: user.goalSecs });
});

// ── SESSIONS ──
app.post('/sessions/start', requireAuth, (req, res) => {
  const db = loadDB();
  const open = q.openSession(db, req.userId);
  if (open) return res.status(409).json({ error: 'session already active', sessionId: open.id });

  const session = {
    id: uid(),
    userId: req.userId,
    startedAt: Date.now(),
    endedAt: null,
    durationSecs: null,
    method: req.body.method || 'manual',
    note: null,
    createdAt: Date.now()
  };
  db.sessions.push(session);
  saveDB(db);

  // Push to all other tabs
  pushToUser(req.userId, 'session:start', { sessionId: session.id, startedAt: session.startedAt, method: session.method });

  res.json({ sessionId: session.id, startedAt: session.startedAt });
});

app.post('/sessions/end', requireAuth, (req, res) => {
  const { sessionId, note } = req.body;
  const db = loadDB();
  const session = q.sessionById(db, sessionId, req.userId);
  if (!session) return res.status(404).json({ error: 'session not found' });
  if (session.endedAt) return res.status(409).json({ error: 'session already ended' });

  const now = Date.now();
  const durationSecs = Math.floor((now - session.startedAt) / 1000);

  if (durationSecs < 30) {
    db.sessions = db.sessions.filter(s => s.id !== sessionId);
    saveDB(db);
    pushToUser(req.userId, 'session:discard', { sessionId });
    return res.json({ discarded: true, reason: 'session too short' });
  }

  session.endedAt = now;
  session.durationSecs = durationSecs;
  session.note = note || null;
  saveDB(db);

  // Push session end to all other tabs — they will show the summary
  pushToUser(req.userId, 'session:end', { sessionId, startedAt: session.startedAt, endedAt: now, durationSecs });

  res.json({ sessionId, startedAt: session.startedAt, endedAt: now, durationSecs });
});

app.get('/sessions/today', requireAuth, (req, res) => {
  const db = loadDB();
  const today = dayKey(Date.now());
  const all = q.sessionsByUser(db, req.userId);
  const sessions = all
    .filter(s => s.endedAt && dayKey(s.startedAt) === today)
    .sort((a, b) => b.startedAt - a.startedAt)
    .map(({ id, startedAt, endedAt, durationSecs, method, note }) => ({ id, startedAt, endedAt, durationSecs, method, note }));
  const open = q.openSession(db, req.userId);
  res.json({ sessions, activeSession: open ? { id: open.id, started_at: open.startedAt, method: open.method } : null });
});

app.get('/sessions/week', requireAuth, (req, res) => {
  const db = loadDB();
  const sevenAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const sessions = q.sessionsByUser(db, req.userId)
    .filter(s => s.endedAt && s.startedAt >= sevenAgo)
    .sort((a, b) => b.startedAt - a.startedAt)
    .map(({ id, startedAt, endedAt, durationSecs, method }) => ({ id, startedAt, endedAt, durationSecs, method }));
  res.json({ sessions });
});

app.get('/sessions/stats', requireAuth, (req, res) => {
  const db = loadDB();
  const all = q.sessionsByUser(db, req.userId).filter(s => s.endedAt);

  let streak = 0;
  const seen = new Set(all.map(s => dayKey(s.startedAt)));
  for (let i = 0; i < 365; i++) {
    const d = new Date(); d.setDate(d.getDate() - i);
    if (seen.has(d.toISOString().slice(0, 10))) streak++;
    else if (i > 0) break;
  }

  const sevenAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const weekTotal = all.filter(s => s.startedAt >= sevenAgo).reduce((a, s) => a + s.durationSecs, 0);
  const avg = all.length > 0 ? Math.round(all.reduce((a, s) => a + s.durationSecs, 0) / all.length) : 0;

  res.json({ streak, weekTotal, avgSession: avg, totalSessions: all.length });
});

app.get('/health', (req, res) => res.json({ ok: true, time: Date.now() }));

app.listen(PORT, '0.0.0.0', () => console.log(`tracl running on port ${PORT}`));
