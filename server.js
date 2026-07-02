const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
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

app.use(cors());
app.use(express.json());

// ─── CONFIG ────────────────────────────────────────────────────────────────
// TODO: move these to environment variables (process.env.X) before deploying.
const GOOGLE_CLIENT_ID = '627215311300-t7g66rtc5uue1tnr1v622uvd75fappp2.apps.googleusercontent.com';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

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

// ─── WEBSOCKET: room subscriptions ───────────────────────────────────────────
// clients map: roomCode → Set of { ws, username }

const roomClients = new Map();

function broadcast(roomCode, data, excludeWs = null) {
  const clients = roomClients.get(roomCode);
  if (!clients) return;
  const payload = JSON.stringify(data);
  clients.forEach(({ ws }) => {
    if (ws !== excludeWs && ws.readyState === 1) {
      ws.send(payload);
    }
  });
}

wss.on('connection', (ws, req) => {
  let subscribedRoom = null;
  let wsUsername = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // { type: 'auth', token }  -- JWT issued by /auth/login, /auth/register, or /auth/google
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

    // { type: 'subscribe', roomCode }
    if (msg.type === 'subscribe') {
      const code = msg.roomCode;
      const member = roomQueries.getMember.get(code, wsUsername);
      if (!member) {
        ws.send(JSON.stringify({ type: 'error', error: 'Not a member of this room' }));
        return;
      }
      // Leave old room
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
      const code = msg.roomCode;
      const text = (msg.text || '').trim();
      if (!text || text.length > 2000) return;
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

      // Send to all subscribers in the room (including sender for confirmation)
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

// POST /auth/register  { username, password }
app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!/^[a-zA-Z0-9_]{2,20}$/.test(username)) {
    return res.status(400).json({ error: 'Username: 2-20 chars, letters/numbers/underscore only' });
  }
  if (password.length < 4) return res.status(400).json({ error: 'Password too short (min 4 chars)' });
  if (userQueries.exists.get(username)) {
    return res.status(409).json({ error: 'Username already taken' });
  }
  const hash = bcrypt.hashSync(password, 10);
  userQueries.create.run(username, hash);
  const token = signToken(username);
  res.json({ ok: true, username, token });
});

// POST /auth/login  { username, password }
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = userQueries.findByUsername.get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  const token = signToken(user.username);
  res.json({ ok: true, username: user.username, token });
});

// ─── AUTH: Google sign-in ─────────────────────────────────────────────────────

// POST /auth/google  { idToken }
// Verifies the Google ID token. If we already know this Google account,
// logs them straight in. Otherwise returns isNew so the frontend can
// prompt for a username, then call /auth/google/complete.
app.post('/auth/google', async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ error: 'idToken required' });

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

  // Not seen before — hand back a short-lived "pending" token so the
  // frontend can submit a chosen username without re-verifying Google.
  const pendingToken = jwt.sign(
    { googleId, email, pending: true },
    JWT_SECRET,
    { expiresIn: '10m' }
  );
  res.json({ ok: true, isNew: true, email, pendingToken });
});

// POST /auth/google/complete  { pendingToken, username }
app.post('/auth/google/complete', (req, res) => {
  const { pendingToken, username } = req.body;
  if (!pendingToken || !username) {
    return res.status(400).json({ error: 'pendingToken and username required' });
  }
  if (!/^[a-zA-Z0-9_]{2,20}$/.test(username)) {
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

  // Random unusable password placeholder — this account can only log in via Google.
  const placeholderPassword = bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10);
  userQueries.createWithGoogle.run(username, placeholderPassword, payload.googleId);

  const token = signToken(username);
  res.json({ ok: true, username, token });
});

// ─── FRIENDS ──────────────────────────────────────────────────────────────────

// GET /friends  → { accepted, incoming, outgoing }
app.get('/friends', requireAuth, (req, res) => {
  const me = req.username;
  const accepted = friendQueries.getAccepted.all(me, me, me).map(r => r.friend);
  const incoming = friendQueries.getIncoming.all(me).map(r => r.requester);
  const outgoing = friendQueries.getOutgoing.all(me).map(r => r.target);
  res.json({ accepted, incoming, outgoing });
});

// POST /friends/request  { toUser }
app.post('/friends/request', requireAuth, (req, res) => {
  const me = req.username;
  const { toUser } = req.body;
  if (!toUser) return res.status(400).json({ error: 'toUser required' });
  if (toUser.toLowerCase() === me.toLowerCase()) return res.status(400).json({ error: "That's you." });
  if (!userQueries.exists.get(toUser)) return res.status(404).json({ error: "No user with that username." });

  const existing = friendQueries.getRelation.get(me, toUser, toUser, me);
  if (existing) {
    if (existing.status === 'accepted') return res.status(400).json({ error: 'Already friends.' });
    // They already sent us a request → auto-accept
    if (existing.from_user.toLowerCase() === toUser.toLowerCase() && existing.status === 'pending') {
      friendQueries.updateStatus.run('accepted', existing.from_user, existing.to_user);
      return res.json({ ok: true, autoAccepted: true });
    }
    if (existing.status === 'pending') return res.status(400).json({ error: 'Request already sent.' });
  }

  friendQueries.sendRequest.run(me, toUser);
  res.json({ ok: true });
});

// POST /friends/accept  { fromUser }
app.post('/friends/accept', requireAuth, (req, res) => {
  const me = req.username;
  const { fromUser } = req.body;
  const rel = friendQueries.getRelation.get(fromUser, me, me, fromUser);
  if (!rel || rel.status !== 'pending') return res.status(400).json({ error: 'No pending request found.' });
  // Make sure the request was TO us
  if (rel.to_user.toLowerCase() !== me.toLowerCase()) return res.status(403).json({ error: 'Not your request.' });
  friendQueries.updateStatus.run('accepted', rel.from_user, rel.to_user);
  res.json({ ok: true });
});

// POST /friends/decline  { fromUser }
app.post('/friends/decline', requireAuth, (req, res) => {
  const me = req.username;
  const { fromUser } = req.body;
  const rel = friendQueries.getRelation.get(fromUser, me, me, fromUser);
  if (!rel || rel.status !== 'pending') return res.status(400).json({ error: 'No pending request found.' });
  if (rel.to_user.toLowerCase() !== me.toLowerCase()) return res.status(403).json({ error: 'Not your request.' });
  friendQueries.updateStatus.run('declined', rel.from_user, rel.to_user);
  res.json({ ok: true });
});

// ─── ROOMS ────────────────────────────────────────────────────────────────────

// GET /rooms  → list of rooms I'm a member of
app.get('/rooms', requireAuth, (req, res) => {
  const rooms = roomQueries.getUserRooms.all(req.username);
  res.json({ rooms });
});

// POST /rooms/create  { name }
app.post('/rooms/create', requireAuth, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Room name required' });
  const code = generateRoomCode();
  roomQueries.create.run(code, name.trim(), req.username);
  roomQueries.addMember.run(code, req.username, Date.now());
  const room = roomQueries.findByCode.get(code);
  res.json({ ok: true, room: { ...room, member_count: 1 } });
});

// POST /rooms/join  { code }
app.post('/rooms/join', requireAuth, (req, res) => {
  const code = (req.body.code || '').trim().toUpperCase();
  if (!code) return res.status(400).json({ error: 'Code required' });
  const room = roomQueries.findByCode.get(code);
  if (!room) return res.status(404).json({ error: 'No room with that code.' });
  roomQueries.addMember.run(code, req.username, Date.now());
  const memberCount = roomQueries.getMembers.all(code).length;
  res.json({ ok: true, room: { ...room, member_count: memberCount } });
});

// GET /rooms/:code/messages  → messages visible to me
app.get('/rooms/:code/messages', requireAuth, (req, res) => {
  const code = req.params.code.toUpperCase();
  const member = roomQueries.getMember.get(code, req.username);
  if (!member) return res.status(403).json({ error: 'Not a member of this room.' });
  const messages = messageQueries.getForUser.all(req.username, code);
  res.json({ messages });
});

// GET /rooms/:code  → room info
app.get('/rooms/:code', requireAuth, (req, res) => {
  const code = req.params.code.toUpperCase();
  const room = roomQueries.findByCode.get(code);
  if (!room) return res.status(404).json({ error: 'Room not found.' });
  const members = roomQueries.getMembers.all(code);
  res.json({ room: { ...room, members, member_count: members.length } });
});

// ─── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, time: Date.now() }));

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n✅ ChatApp backend running on http://localhost:${PORT}`);
  console.log(`🔌 WebSocket ready on ws://localhost:${PORT}`);
  console.log(`📁 Database: ${require('path').join(__dirname, 'chatapp.db')}\n`);
});