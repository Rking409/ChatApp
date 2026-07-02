const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const {
  userQueries,
  friendQueries,
  roomQueries,
  messageQueries,
  generateRoomCode,
} = require('./db');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ─── CONFIG (all from environment — no fallbacks for secrets) ───────────────
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}
if (!GOOGLE_CLIENT_ID) {
  console.error('FATAL: GOOGLE_CLIENT_ID environment variable is not set. Refusing to start.');
  process.exit(1);
}
if (ALLOWED_ORIGINS.length === 0) {
  console.warn('WARNING: ALLOWED_ORIGINS is not set — CORS will block all browser origins by default.');
}

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ─── SECURITY MIDDLEWARE ─────────────────────────────────────────────────────
app.use(helmet());

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (no Origin header, e.g. curl/health checks)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
}));

app.use(express.json({ limit: '100kb' })); // cap body size — cheap DoS protection

// General API rate limit — generous, just stops abuse/scripted hammering.
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120, // 120 requests/min per IP across the API
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

// Strict limiter for auth endpoints — brute force / credential stuffing protection.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // 20 attempts per 15 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again later.' },
});

// ─── AUTH MIDDLEWARE (JWT-based) ─────────────────────────────────────────────
// Frontend sends: Authorization: Bearer <jwt>

function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const token = auth.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    const user = userQueries.findByUsername.get(payload.username);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });
    req.username = user.username;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

function signToken(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });
}

// ─── INPUT VALIDATION HELPERS ────────────────────────────────────────────────
const USERNAME_RE = /^[a-zA-Z0-9_]{2,20}$/;
const MAX_ROOM_NAME_LEN = 40;
const MAX_MESSAGE_LEN = 2000;
const MAX_ROOM_CODE_LEN = 10; // real codes are 6 chars; cap generously to reject garbage early

function isValidUsername(u) {
  return typeof u === 'string' && USERNAME_RE.test(u);
}

// ─── WEBSOCKET: room subscriptions ───────────────────────────────────────────
// clients map: roomCode → Set of { ws, username }

const roomClients = new Map();

// Basic per-connection rate limiting for WS messages (spam protection).
const WS_MSG_WINDOW_MS = 10 * 1000;
const WS_MSG_MAX = 30; // 30 messages per 10s per connection

wss.on('connection', (ws, req) => {
  let subscribedRoom = null;
  let wsUsername = null;
  let msgTimestamps = [];

  function isRateLimited() {
    const now = Date.now();
    msgTimestamps = msgTimestamps.filter(t => now - t < WS_MSG_WINDOW_MS);
    if (msgTimestamps.length >= WS_MSG_MAX) return true;
    msgTimestamps.push(now);
    return false;
  }

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg.type !== 'string') return;

    // { type: 'auth', token }
    if (msg.type === 'auth') {
      try {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        const user = userQueries.findByUsername.get(payload.username);
        if (!user) {
          ws.send(JSON.stringify({ type: 'error', error: 'Invalid session' }));
          return;
        }
        wsUsername = user.username;
        ws.send(JSON.stringify({ type: 'authed', username: wsUsername }));
      } catch (e) {
        ws.send(JSON.stringify({ type: 'error', error: 'Invalid or expired session' }));
      }
      return;
    }

    if (!wsUsername) {
      ws.send(JSON.stringify({ type: 'error', error: 'Not authenticated' }));
      return;
    }

    if (isRateLimited()) {
      ws.send(JSON.stringify({ type: 'error', error: 'Sending too fast — slow down.' }));
      return;
    }

    // { type: 'subscribe', roomCode }
    if (msg.type === 'subscribe') {
      const code = typeof msg.roomCode === 'string' ? msg.roomCode.slice(0, MAX_ROOM_CODE_LEN) : '';
      if (!code) return;
      const member = roomQueries.getMember.get(code, wsUsername);
      if (!member) {
        ws.send(JSON.stringify({ type: 'error', error: 'Not a member of this room' }));
        return;
      }
      if (subscribedRoom) {
        const old = roomClients.get(subscribedRoom);
        if (old) old.forEach(c => { if (c.ws === ws) old.delete(c); });
      }
      subscribedRoom = code;
      if (!roomClients.has(code)) roomClients.set(code, new Set());
      roomClients.get(code).add({ ws, username: wsUsername });
      ws.send(JSON.stringify({ type: 'subscribed', roomCode: code }));
      return;
    }

    // { type: 'message', roomCode, text }
    if (msg.type === 'message') {
      const code = typeof msg.roomCode === 'string' ? msg.roomCode.slice(0, MAX_ROOM_CODE_LEN) : '';
      const text = typeof msg.text === 'string' ? msg.text.trim() : '';
      if (!code || !text || text.length > MAX_MESSAGE_LEN) return;
      const member = roomQueries.getMember.get(code, wsUsername);
      if (!member) return;

      const sentAt = Date.now();
      messageQueries.insert.run(code, wsUsername, text, sentAt);

      const packet = {
        type: 'message',
        roomCode: code,
        id: sentAt + '-' + Math.random().toString(36).slice(2, 6),
        sender: wsUsername,
        text,
        sent_at: sentAt,
      };

      const clients = roomClients.get(code);
      if (clients) {
        const payload = JSON.stringify(packet);
        clients.forEach(({ ws: cws }) => {
          if (cws.readyState === 1) cws.send(payload);
        });
      }
      return;
    }
  });

  ws.on('close', () => {
    if (subscribedRoom) {
      const clients = roomClients.get(subscribedRoom);
      if (clients) clients.forEach(c => { if (c.ws === ws) clients.delete(c); });
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  REST ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ─── AUTH: classic username/password ─────────────────────────────────────────

app.post('/auth/register', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Username: 2-20 chars, letters/numbers/underscore only' });
  }
  if (typeof password !== 'string' || password.length < 4 || password.length > 200) {
    return res.status(400).json({ error: 'Password must be 4-200 characters' });
  }
  if (userQueries.exists.get(username)) {
    return res.status(409).json({ error: 'Username already taken' });
  }
  const hash = bcrypt.hashSync(password, 10);
  userQueries.create.run(username, hash);
  const token = signToken(username);
  res.json({ ok: true, username, token });
});

app.post('/auth/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password required' });
  }
  const user = userQueries.findByUsername.get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  const token = signToken(user.username);
  res.json({ ok: true, username: user.username, token });
});

// ─── AUTH: Google sign-in ─────────────────────────────────────────────────────

app.post('/auth/google', authLimiter, async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken || typeof idToken !== 'string') return res.status(400).json({ error: 'idToken required' });

  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: GOOGLE_CLIENT_ID,
    });
    payload = ticket.getPayload();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid Google token' });
  }

  const googleId = payload.sub;
  const email = payload.email;

  const existing = userQueries.findByGoogleId.get(googleId);
  if (existing) {
    const token = signToken(existing.username);
    return res.json({ ok: true, isNew: false, username: existing.username, token });
  }

  const pendingToken = jwt.sign(
    { googleId, email, pending: true },
    JWT_SECRET,
    { expiresIn: '10m' }
  );
  res.json({ ok: true, isNew: true, email, pendingToken });
});

app.post('/auth/google/complete', authLimiter, (req, res) => {
  const { pendingToken, username } = req.body || {};
  if (!pendingToken || !username) {
    return res.status(400).json({ error: 'pendingToken and username required' });
  }
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Username: 2-20 chars, letters/numbers/underscore only' });
  }

  let payload;
  try {
    payload = jwt.verify(pendingToken, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: 'Pending session expired, please sign in with Google again' });
  }
  if (!payload.pending || !payload.googleId) {
    return res.status(400).json({ error: 'Invalid pending token' });
  }

  if (userQueries.exists.get(username)) {
    return res.status(409).json({ error: 'Username already taken' });
  }
  if (userQueries.findByGoogleId.get(payload.googleId)) {
    return res.status(409).json({ error: 'This Google account is already linked to a user' });
  }

  const placeholderPassword = bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10);
  userQueries.createWithGoogle.run(username, placeholderPassword, payload.googleId);

  const token = signToken(username);
  res.json({ ok: true, username, token });
});

// ─── FRIENDS ──────────────────────────────────────────────────────────────────

app.get('/friends', requireAuth, (req, res) => {
  const me = req.username;
  const accepted = friendQueries.getAccepted.all(me, me, me).map(r => r.friend);
  const incoming = friendQueries.getIncoming.all(me).map(r => r.requester);
  const outgoing = friendQueries.getOutgoing.all(me).map(r => r.target);
  res.json({ accepted, incoming, outgoing });
});

app.post('/friends/request', requireAuth, (req, res) => {
  const me = req.username;
  const { toUser } = req.body || {};
  if (!toUser || typeof toUser !== 'string' || !isValidUsername(toUser)) {
    return res.status(400).json({ error: 'Valid toUser required' });
  }
  if (toUser.toLowerCase() === me.toLowerCase()) return res.status(400).json({ error: "That's you." });
  if (!userQueries.exists.get(toUser)) return res.status(404).json({ error: "No user with that username." });

  const existing = friendQueries.getRelation.get(me, toUser, toUser, me);
  if (existing) {
    if (existing.status === 'accepted') return res.status(400).json({ error: 'Already friends.' });
    if (existing.from_user.toLowerCase() === toUser.toLowerCase() && existing.status === 'pending') {
      friendQueries.updateStatus.run('accepted', existing.from_user, existing.to_user);
      return res.json({ ok: true, autoAccepted: true });
    }
    if (existing.status === 'pending') return res.status(400).json({ error: 'Request already sent.' });
  }

  friendQueries.sendRequest.run(me, toUser);
  res.json({ ok: true });
});

app.post('/friends/accept', requireAuth, (req, res) => {
  const me = req.username;
  const { fromUser } = req.body || {};
  if (!fromUser || typeof fromUser !== 'string') return res.status(400).json({ error: 'fromUser required' });
  const rel = friendQueries.getRelation.get(fromUser, me, me, fromUser);
  if (!rel || rel.status !== 'pending') return res.status(400).json({ error: 'No pending request found.' });
  if (rel.to_user.toLowerCase() !== me.toLowerCase()) return res.status(403).json({ error: 'Not your request.' });
  friendQueries.updateStatus.run('accepted', rel.from_user, rel.to_user);
  res.json({ ok: true });
});

app.post('/friends/decline', requireAuth, (req, res) => {
  const me = req.username;
  const { fromUser } = req.body || {};
  if (!fromUser || typeof fromUser !== 'string') return res.status(400).json({ error: 'fromUser required' });
  const rel = friendQueries.getRelation.get(fromUser, me, me, fromUser);
  if (!rel || rel.status !== 'pending') return res.status(400).json({ error: 'No pending request found.' });
  if (rel.to_user.toLowerCase() !== me.toLowerCase()) return res.status(403).json({ error: 'Not your request.' });
  friendQueries.updateStatus.run('declined', rel.from_user, rel.to_user);
  res.json({ ok: true });
});

// ─── ROOMS ────────────────────────────────────────────────────────────────────

app.get('/rooms', requireAuth, (req, res) => {
  const rooms = roomQueries.getUserRooms.all(req.username);
  res.json({ rooms });
});

app.post('/rooms/create', requireAuth, (req, res) => {
  const { name } = req.body || {};
  if (!name || typeof name !== 'string' || !name.trim() || name.trim().length > MAX_ROOM_NAME_LEN) {
    return res.status(400).json({ error: `Room name required (max ${MAX_ROOM_NAME_LEN} chars)` });
  }
  const code = generateRoomCode();
  roomQueries.create.run(code, name.trim(), req.username);
  roomQueries.addMember.run(code, req.username, Date.now());
  const room = roomQueries.findByCode.get(code);
  res.json({ ok: true, room: { ...room, member_count: 1 } });
});

app.post('/rooms/join', requireAuth, (req, res) => {
  const raw = req.body && req.body.code;
  if (typeof raw !== 'string' || !raw.trim() || raw.trim().length > MAX_ROOM_CODE_LEN) {
    return res.status(400).json({ error: 'Valid code required' });
  }
  const code = raw.trim().toUpperCase();
  const room = roomQueries.findByCode.get(code);
  if (!room) return res.status(404).json({ error: 'No room with that code.' });
  roomQueries.addMember.run(code, req.username, Date.now());
  const memberCount = roomQueries.getMembers.all(code).length;
  res.json({ ok: true, room: { ...room, member_count: memberCount } });
});

app.get('/rooms/:code/messages', requireAuth, (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  const member = roomQueries.getMember.get(code, req.username);
  if (!member) return res.status(403).json({ error: 'Not a member of this room.' });
  const messages = messageQueries.getForUser.all(req.username, code);
  res.json({ messages });
});

app.get('/rooms/:code', requireAuth, (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  const room = roomQueries.findByCode.get(code);
  if (!room) return res.status(404).json({ error: 'Room not found.' });
  const members = roomQueries.getMembers.all(code);
  res.json({ room: { ...room, members, member_count: members.length } });
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, time: Date.now() }));

// ─── FALLBACK ERROR HANDLER ──────────────────────────────────────────────────
// Catches CORS rejections and anything else thrown synchronously in routes,
// so we never leak stack traces to clients.
app.use((err, req, res, next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n✅ ChatApp backend running on http://localhost:${PORT}`);
  console.log(`🔌 WebSocket ready on ws://localhost:${PORT}`);
  console.log(`📁 Database: ${require('path').join(__dirname, 'chatapp.db')}\n`);
});