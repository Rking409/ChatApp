require('express-async-errors');
const express = require('express');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const multer = require('multer');
const { OAuth2Client } = require('google-auth-library');
const {
  userQueries,
  friendQueries,
  roomQueries,
  messageQueries,
  dailyPhotoQueries,
  keyQueries,
  adminQueries,
  generateRoomCode,
  initSchema,
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

const ADMIN_TOKEN_HASH = process.env.ADMIN_TOKEN_HASH || '';
if (!ADMIN_TOKEN_HASH) {
  console.error('FATAL: ADMIN_TOKEN_HASH environment variable is not set. Admin endpoints will be disabled.');
}

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ─── MULTER: profile picture uploads ──────────────────────────────────────────
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    cb(null, `${req.username}_${Date.now()}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Only images allowed (jpg, png, gif, webp)'));
  },
});

// ─── MULTER: daily photo uploads ──────────────────────────────────────────────
const DAILY_UPLOAD_DIR = path.join(__dirname, 'uploads', 'daily');
const dailyStorage = multer.diskStorage({
  destination: DAILY_UPLOAD_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    cb(null, `${req.username}_${Date.now()}${ext}`);
  },
});
const dailyUpload = multer({
  storage: dailyStorage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Only images allowed (jpg, png, gif, webp)'));
  },
});

// ─── HELPER: auto-friend room members ─────────────────────────────────────────
async function autoFriendMembers(roomCode, newUsername) {
  const others = await roomQueries.getMembersExcept(roomCode, newUsername);
  const now = Date.now();
  for (const member of others) {
    await friendQueries.insertAccepted(newUsername, member.username, now);
    await friendQueries.insertAccepted(member.username, newUsername, now);
  }
}

// ─── SECURITY MIDDLEWARE ─────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginOpenerPolicy: { policy: "unsafe-none" },
}));

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (no Origin header, e.g. curl/health checks)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
}));

app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/admin', express.static(path.join(__dirname, '..', 'frontend')));
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

async function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const token = auth.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await userQueries.findByUsername(payload.username);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });
    req.username = user.username;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

function requireAdminToken(req, res, next) {
  if (!ADMIN_TOKEN_HASH) return res.status(403).json({ error: 'Admin access not configured' });
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Admin token required' });
  }
  const token = auth.slice(7);
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  if (hash !== ADMIN_TOKEN_HASH) {
    return res.status(403).json({ error: 'Invalid admin token' });
  }
  next();
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

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (!msg || typeof msg.type !== 'string') return;

    // { type: 'auth', token }
    if (msg.type === 'auth') {
      try {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        const user = await userQueries.findByUsername(payload.username);
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
      const member = await roomQueries.getMember(code, wsUsername);
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
      const member = await roomQueries.getMember(code, wsUsername);
      if (!member) return;

      const sentAt = Date.now();
      const encrypted = msg.encrypted ? 1 : 0;
      const encIv = msg.encIv || null;
      const msgId = await messageQueries.insertEncrypted(code, wsUsername, text, sentAt, encrypted, encIv);

      const packet = {
        type: 'message',
        roomCode: code,
        msgId,
        id: sentAt + '-' + Math.random().toString(36).slice(2, 6),
        sender: wsUsername,
        text,
        sent_at: sentAt,
        edited: 0,
        encrypted,
        encIv,
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

    // { type: 'typing', roomCode }
    if (msg.type === 'typing') {
      const code = typeof msg.roomCode === 'string' ? msg.roomCode.slice(0, MAX_ROOM_CODE_LEN) : '';
      if (!code) return;
      const clients = roomClients.get(code);
      if (clients) {
        const packet = JSON.stringify({ type: 'typing', roomCode: code, username: wsUsername });
        clients.forEach(({ ws: cws, username }) => {
          if (cws.readyState === 1 && username !== wsUsername) cws.send(packet);
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
  if (await userQueries.exists(username)) {
    return res.status(409).json({ error: 'Username already taken' });
  }
  const hash = bcrypt.hashSync(password, 10);
  await userQueries.create(username, hash);
  const token = signToken(username);
  const user = await userQueries.findByUsername(username);
  res.json({ ok: true, username, token, avatar_url: user.avatar_url || null });
});

app.post('/auth/login', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password required' });
  }
  const user = await userQueries.findByUsername(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  const token = signToken(user.username);
  res.json({ ok: true, username: user.username, token, avatar_url: user.avatar_url || null });
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

  const existing = await userQueries.findByGoogleId(googleId);
  if (existing) {
    const token = signToken(existing.username);
    return res.json({ ok: true, isNew: false, username: existing.username, token, avatar_url: existing.avatar_url || null });
  }

  const pendingToken = jwt.sign(
    { googleId, email, pending: true },
    JWT_SECRET,
    { expiresIn: '10m' }
  );
  res.json({ ok: true, isNew: true, email, pendingToken });
});

app.post('/auth/google/complete', authLimiter, async (req, res) => {
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

  if (await userQueries.exists(username)) {
    return res.status(409).json({ error: 'Username already taken' });
  }
  if (await userQueries.findByGoogleId(payload.googleId)) {
    return res.status(409).json({ error: 'This Google account is already linked to a user' });
  }

  const placeholderPassword = bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10);
  await userQueries.createWithGoogle(username, placeholderPassword, payload.googleId);

  const token = signToken(username);
  const user = await userQueries.findByUsername(username);
  res.json({ ok: true, username, token, avatar_url: user.avatar_url || null });
});

// ─── FRIENDS ──────────────────────────────────────────────────────────────────

app.get('/friends', requireAuth, async (req, res) => {
  const me = req.username;
  const accepted = (await friendQueries.getAccepted(me)).map(r => r.friend);
  const incoming = (await friendQueries.getIncoming(me)).map(r => r.requester);
  const outgoing = (await friendQueries.getOutgoing(me)).map(r => r.target);
  res.json({ accepted, incoming, outgoing });
});

app.post('/friends/request', requireAuth, async (req, res) => {
  const me = req.username;
  const { toUser } = req.body || {};
  if (!toUser || typeof toUser !== 'string' || !isValidUsername(toUser)) {
    return res.status(400).json({ error: 'Valid toUser required' });
  }
  if (toUser.toLowerCase() === me.toLowerCase()) return res.status(400).json({ error: "That's you." });
  if (!await userQueries.exists(toUser)) return res.status(404).json({ error: "No user with that username." });

  const existing = await friendQueries.getRelation(me, toUser);
  if (existing) {
    if (existing.status === 'accepted') return res.status(400).json({ error: 'Already friends.' });
    if (existing.from_user.toLowerCase() === toUser.toLowerCase() && existing.status === 'pending') {
      await friendQueries.updateStatus('accepted', existing.from_user, existing.to_user);
      return res.json({ ok: true, autoAccepted: true });
    }
    if (existing.status === 'pending') return res.status(400).json({ error: 'Request already sent.' });
  }

  await friendQueries.sendRequest(me, toUser);
  res.json({ ok: true });
});

app.post('/friends/accept', requireAuth, async (req, res) => {
  const me = req.username;
  const { fromUser } = req.body || {};
  if (!fromUser || typeof fromUser !== 'string') return res.status(400).json({ error: 'fromUser required' });
  const rel = await friendQueries.getRelation(fromUser, me);
  if (!rel || rel.status !== 'pending') return res.status(400).json({ error: 'No pending request found.' });
  if (rel.to_user.toLowerCase() !== me.toLowerCase()) return res.status(403).json({ error: 'Not your request.' });
  await friendQueries.updateStatus('accepted', rel.from_user, rel.to_user);
  res.json({ ok: true });
});

app.post('/friends/decline', requireAuth, async (req, res) => {
  const me = req.username;
  const { fromUser } = req.body || {};
  if (!fromUser || typeof fromUser !== 'string') return res.status(400).json({ error: 'fromUser required' });
  const rel = await friendQueries.getRelation(fromUser, me);
  if (!rel || rel.status !== 'pending') return res.status(400).json({ error: 'No pending request found.' });
  if (rel.to_user.toLowerCase() !== me.toLowerCase()) return res.status(403).json({ error: 'Not your request.' });
  await friendQueries.updateStatus('declined', rel.from_user, rel.to_user);
  res.json({ ok: true });
});

// ─── ROOMS ────────────────────────────────────────────────────────────────────

app.get('/rooms', requireAuth, async (req, res) => {
  const rooms = await roomQueries.getUserRooms(req.username);
  // Attach unread counts
  for (const room of rooms) {
    const unread = await messageQueries.getUnreadCount(req.username, room.code);
    room.unread = unread ? unread.count : 0;
  }
  res.json({ rooms });
});

const HEX_COLOR_RE = /^#[0-9A-Fa-f]{6}$/;
const DEFAULT_ROOM_COLOR = '#3B82F6';

app.post('/rooms/create', requireAuth, async (req, res) => {
  const { name, color } = req.body || {};
  if (!name || typeof name !== 'string' || !name.trim() || name.trim().length > MAX_ROOM_NAME_LEN) {
    return res.status(400).json({ error: `Room name required (max ${MAX_ROOM_NAME_LEN} chars)` });
  }
  const roomColor = (typeof color === 'string' && HEX_COLOR_RE.test(color)) ? color : DEFAULT_ROOM_COLOR;
  const code = await generateRoomCode();
  await roomQueries.create(code, name.trim(), req.username, roomColor);
  await roomQueries.addMember(code, req.username, Date.now());
  await autoFriendMembers(code, req.username);
  const room = await roomQueries.findByCode(code);
  res.json({ ok: true, room: { ...room, member_count: 1 } });
});

app.post('/rooms/:code/color', requireAuth, async (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  const { color } = req.body || {};
  if (typeof color !== 'string' || !HEX_COLOR_RE.test(color)) {
    return res.status(400).json({ error: 'Color must be a hex value like #3B82F6' });
  }
  const member = await roomQueries.getMember(code, req.username);
  if (!member) return res.status(403).json({ error: 'Not a member of this room.' });
  const room = await roomQueries.findByCode(code);
  if (!room) return res.status(404).json({ error: 'Room not found.' });
  await roomQueries.setColor(color, code);
  res.json({ ok: true, color });
});

app.post('/rooms/join', requireAuth, async (req, res) => {
  const raw = req.body && req.body.code;
  if (typeof raw !== 'string' || !raw.trim() || raw.trim().length > MAX_ROOM_CODE_LEN) {
    return res.status(400).json({ error: 'Valid code required' });
  }
  const code = raw.trim().toUpperCase();
  const room = await roomQueries.findByCode(code);
  if (!room) return res.status(404).json({ error: 'No room with that code.' });
  await roomQueries.addMember(code, req.username, Date.now());
  await autoFriendMembers(code, req.username);
  const members = await roomQueries.getMembers(code);
  res.json({ ok: true, room: { ...room, member_count: members.length } });
});


app.get('/rooms/:code/messages', requireAuth, async (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  const member = await roomQueries.getMember(code, req.username);
  if (!member) return res.status(403).json({ error: 'Not a member of this room.' });
  const messages = await messageQueries.getForUser(req.username, code);
  const reactions = await messageQueries.getReactionsForMessages(code);
  // Group reactions by message_id
  const reactionsByMsg = {};
  for (const r of reactions) {
    if (!reactionsByMsg[r.message_id]) reactionsByMsg[r.message_id] = [];
    reactionsByMsg[r.message_id].push({ username: r.username, emoji: r.emoji });
  }
  res.json({ messages, reactionsByMsg });
});

app.get('/rooms/:code', requireAuth, async (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  const room = await roomQueries.findByCode(code);
  if (!room) return res.status(404).json({ error: 'Room not found.' });
  const members = await roomQueries.getMembers(code);
  res.json({ room: { ...room, members, member_count: members.length } });
});

// ─── USERS: profile picture upload ────────────────────────────────────────────

app.get('/users/me', requireAuth, async (req, res) => {
  const user = await userQueries.findByUsername(req.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ username: user.username, avatar_url: user.avatar_url || null });
});

app.post('/users/avatar', requireAuth, (req, res, next) => {
  upload.single('avatar')(req, res, async (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'Image must be under 5 MB' });
      }
      return res.status(400).json({ error: err.message || 'Upload failed' });
    }
    if (!req.file) return res.status(400).json({ error: 'No file provided' });
    const avatarUrl = `/uploads/${req.file.filename}`;
    await userQueries.setAvatarUrl(avatarUrl, req.username);
    res.json({ ok: true, avatar_url: avatarUrl });
  });
});

// ─── E2E ENCRYPTION KEYS ───────────────────────────────────────────────────────

app.post('/users/key', requireAuth, async (req, res) => {
  const { public_key } = req.body || {};
  if (!public_key || typeof public_key !== 'string') return res.status(400).json({ error: 'public_key required' });
  await keyQueries.setPublicKey(req.username, public_key, Date.now());
  res.json({ ok: true });
});

app.get('/users/:username/key', requireAuth, async (req, res) => {
  const key = await keyQueries.getPublicKey(req.params.username);
  if (!key) return res.status(404).json({ error: 'No key found' });
  res.json({ public_key: key.public_key });
});

app.post('/rooms/:code/keys', requireAuth, async (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  const member = await roomQueries.getMember(code, req.username);
  if (!member) return res.status(403).json({ error: 'Not a member' });
  const { encrypted_key } = req.body || {};
  if (!encrypted_key || typeof encrypted_key !== 'string') return res.status(400).json({ error: 'encrypted_key required' });
  await keyQueries.storeRoomKey(code, req.username, encrypted_key);
  res.json({ ok: true });
});

app.get('/rooms/:code/keys', requireAuth, async (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  const member = await roomQueries.getMember(code, req.username);
  if (!member) return res.status(403).json({ error: 'Not a member' });
  const keys = await keyQueries.getRoomKeys(code);
  res.json({ keys });
});

// ─── ADMIN DATA ───────────────────────────────────────────────────────────────────

app.get('/admin/stats', requireAdminToken, async (req, res) => {
  res.json({
    users: (await adminQueries.countUsers()).count,
    rooms: (await adminQueries.countRooms()).count,
    messages: (await adminQueries.countMessages()).count,
    photos: (await adminQueries.countPhotos()).count,
  });
});

app.get('/admin/users', requireAdminToken, async (req, res) => {
  res.json({ users: await adminQueries.getAllUsers() });
});

app.get('/admin/rooms', requireAdminToken, async (req, res) => {
  const rooms = await adminQueries.getAllRooms();
  const members = await adminQueries.getAllMembers();
  const membersByRoom = {};
  for (const m of members) {
    if (!membersByRoom[m.room_code]) membersByRoom[m.room_code] = [];
    membersByRoom[m.room_code].push(m.username);
  }
  for (const r of rooms) r.members = membersByRoom[r.code] || [];
  res.json({ rooms });
});

app.get('/admin/messages', requireAdminToken, async (req, res) => {
  res.json({ messages: await adminQueries.getAllMessages() });
});

app.get('/admin/friends', requireAdminToken, async (req, res) => {
  res.json({ friends: await adminQueries.getAllFriends() });
});

app.get('/admin/photos', requireAdminToken, async (req, res) => {
  res.json({ photos: await adminQueries.getAllPhotos() });
});

// ─── DAILY MOMENTS ─────────────────────────────────────────────────────────────

app.post('/rooms/:code/photos', requireAuth, (req, res, next) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  (async () => {
    const member = await roomQueries.getMember(code, req.username);
    if (!member) return res.status(403).json({ error: 'Not a member of this room.' });
    dailyUpload.single('photo')(req, res, async (err) => {
      if (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ error: 'Image must be under 10 MB' });
        }
        return res.status(400).json({ error: err.message || 'Upload failed' });
      }
      if (!req.file) return res.status(400).json({ error: 'No file provided' });
      const photoUrl = `/uploads/daily/${req.file.filename}`;
      const now = Date.now();
      const dayDate = new Date().toISOString().slice(0, 10);
      const encrypted = req.body.encrypted ? 1 : 0;
      const encIv = req.body.encIv || null;
      await dailyPhotoQueries.insertEncrypted(code, req.username, photoUrl, now, dayDate, encrypted, encIv);
      res.json({ ok: true, photo_url: photoUrl, taken_at: now, encrypted, encIv });
    });
  })();
});

app.get('/rooms/:code/photos', requireAuth, async (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  const member = await roomQueries.getMember(code, req.username);
  if (!member) return res.status(403).json({ error: 'Not a member of this room.' });
  const date = req.query.date || new Date().toISOString().slice(0, 10);
  const photos = await dailyPhotoQueries.getForRoomAndDay(code, date);
  res.json({ photos });
});

app.get('/moments', requireAuth, async (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const photos = await dailyPhotoQueries.getForUserToday(req.username, today);
  // Group by room_code
  const rooms = {};
  for (const p of photos) {
    if (!rooms[p.room_code]) rooms[p.room_code] = { room_code: p.room_code, photos: [] };
    rooms[p.room_code].photos.push(p);
  }
  // Fetch room names
  const result = [];
  for (const code of Object.keys(rooms)) {
    const room = await roomQueries.findByCode(code);
    if (room) {
      result.push({
        room_code: code,
        room_name: room.name,
        room_color: room.color,
        photos: rooms[code].photos,
      });
    }
  }
  res.json({ rooms: result });
});

// ─── MESSAGE REACTIONS ─────────────────────────────────────────────────────────

app.post('/messages/:id/reaction', requireAuth, async (req, res) => {
  const msgId = parseInt(req.params.id, 10);
  if (!msgId) return res.status(400).json({ error: 'Invalid message id' });
  const { emoji } = req.body || {};
  if (!emoji || typeof emoji !== 'string' || emoji.length > 10) return res.status(400).json({ error: 'Invalid emoji' });
  const msg = await messageQueries.findById(msgId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  const member = await roomQueries.getMember(msg.room_code, req.username);
  if (!member) return res.status(403).json({ error: 'Not a member of this room' });
  // Toggle: if reaction exists, remove it; otherwise add it
  const existing = (await messageQueries.getReactions(msgId)).filter(r => r.username === req.username && r.emoji === emoji);
  if (existing.length) {
    await messageQueries.removeReaction(msgId, req.username, emoji);
    res.json({ ok: true, action: 'removed', emoji });
  } else {
    await messageQueries.toggleReaction(msgId, msg.room_code, req.username, emoji);
    res.json({ ok: true, action: 'added', emoji });
  }
});

app.get('/messages/:id/reactions', requireAuth, async (req, res) => {
  const msgId = parseInt(req.params.id, 10);
  if (!msgId) return res.status(400).json({ error: 'Invalid message id' });
  const reactions = await messageQueries.getReactions(msgId);
  res.json({ reactions });
});

// ─── MESSAGE EDIT / DELETE ─────────────────────────────────────────────────────

app.put('/messages/:id', requireAuth, async (req, res) => {
  const msgId = parseInt(req.params.id, 10);
  if (!msgId) return res.status(400).json({ error: 'Invalid message id' });
  const { text } = req.body || {};
  if (!text || typeof text !== 'string' || !text.trim() || text.length > MAX_MESSAGE_LEN) {
    return res.status(400).json({ error: 'Text required' });
  }
  const msg = await messageQueries.findById(msgId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender.toLowerCase() !== req.username.toLowerCase()) return res.status(403).json({ error: 'Not your message' });
  await messageQueries.updateText(text.trim(), msgId);
  // Broadcast edit via WS
  const clients = roomClients.get(msg.room_code);
  if (clients) {
    const packet = JSON.stringify({ type: 'edit', msgId, text: text.trim(), roomCode: msg.room_code });
    clients.forEach(({ ws: cws }) => { if (cws.readyState === 1) cws.send(packet); });
  }
  res.json({ ok: true });
});

app.delete('/messages/:id', requireAuth, async (req, res) => {
  const msgId = parseInt(req.params.id, 10);
  if (!msgId) return res.status(400).json({ error: 'Invalid message id' });
  const msg = await messageQueries.findById(msgId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender.toLowerCase() !== req.username.toLowerCase()) return res.status(403).json({ error: 'Not your message' });
  await messageQueries.markDeleted(msgId);
  // Broadcast delete via WS
  const clients = roomClients.get(msg.room_code);
  if (clients) {
    const packet = JSON.stringify({ type: 'delete', msgId, roomCode: msg.room_code });
    clients.forEach(({ ws: cws }) => { if (cws.readyState === 1) cws.send(packet); });
  }
  res.json({ ok: true });
});

// ─── UNREAD TRACKING ───────────────────────────────────────────────────────────

app.post('/rooms/:code/read', requireAuth, async (req, res) => {
  const code = req.params.code.slice(0, MAX_ROOM_CODE_LEN).toUpperCase();
  await messageQueries.markRead(Date.now(), code, req.username);
  res.json({ ok: true });
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

initSchema()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`\n✅ ChatApp backend running on http://localhost:${PORT}`);
      console.log(`🔌 WebSocket ready on ws://localhost:${PORT}`);
      console.log(`🐘 Database: PostgreSQL\n`);
    });
  })
  .catch(err => {
    console.error('FATAL: Failed to initialize database schema:', err);
    process.exit(1);
  });