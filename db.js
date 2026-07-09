const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'chatapp.db'));

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─── CREATE TABLES ───────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password  TEXT    NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS friends (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user  TEXT NOT NULL COLLATE NOCASE,
    to_user    TEXT NOT NULL COLLATE NOCASE,
    status     TEXT NOT NULL DEFAULT 'pending',  -- pending | accepted | declined
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE(from_user, to_user)
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    code       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    owner      TEXT NOT NULL COLLATE NOCASE,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS room_members (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    room_code TEXT NOT NULL,
    username  TEXT NOT NULL COLLATE NOCASE,
    joined_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE(room_code, username)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    room_code TEXT    NOT NULL,
    sender    TEXT    NOT NULL COLLATE NOCASE,
    text      TEXT    NOT NULL,
    sent_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_code, sent_at);
  CREATE INDEX IF NOT EXISTS idx_friends_users ON friends(from_user, to_user);

  CREATE TABLE IF NOT EXISTS daily_photos (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    room_code  TEXT    NOT NULL,
    username   TEXT    NOT NULL COLLATE NOCASE,
    photo_url  TEXT    NOT NULL,
    taken_at   INTEGER NOT NULL,
    day_date   TEXT    NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_daily_photos_room_day ON daily_photos(room_code, day_date);
`);

// ─── MIGRATION: add google_id column for Google sign-in users ───────────────
const userCols = db.prepare("PRAGMA table_info(users)").all();
const hasGoogleId = userCols.some(c => c.name === 'google_id');
if (!hasGoogleId) {
  db.exec(`ALTER TABLE users ADD COLUMN google_id TEXT`);
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id)`);
}

// ─── MIGRATION: add avatar_url column for profile pictures ──────────────────
const hasAvatarUrl = userCols.some(c => c.name === 'avatar_url');
if (!hasAvatarUrl) {
  db.exec(`ALTER TABLE users ADD COLUMN avatar_url TEXT`);
}

// ─── MIGRATION: add color column for per-room custom colors ─────────────────
const roomCols = db.prepare("PRAGMA table_info(rooms)").all();
const hasColor = roomCols.some(c => c.name === 'color');
if (!hasColor) {
  db.exec(`ALTER TABLE rooms ADD COLUMN color TEXT NOT NULL DEFAULT '#3B82F6'`);
}

// ─── USER QUERIES ─────────────────────────────────────────────────────────────

const userQueries = {
  findByUsername: db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE'),
  create: db.prepare('INSERT INTO users (username, password) VALUES (?, ?)'),
  exists: db.prepare('SELECT 1 FROM users WHERE username = ? COLLATE NOCASE'),
  findByGoogleId: db.prepare('SELECT * FROM users WHERE google_id = ?'),
  createWithGoogle: db.prepare(
    'INSERT INTO users (username, password, google_id) VALUES (?, ?, ?)'
  ),
  setAvatarUrl: db.prepare('UPDATE users SET avatar_url = ? WHERE username = ?'),
};

// ─── FRIEND QUERIES ───────────────────────────────────────────────────────────

const friendQueries = {
  getRelation: db.prepare(`
    SELECT * FROM friends
    WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
  `),
  sendRequest: db.prepare(`
    INSERT INTO friends (from_user, to_user, status) VALUES (?, ?, 'pending')
  `),
  updateStatus: db.prepare(`
    UPDATE friends SET status = ? WHERE from_user = ? AND to_user = ?
  `),
  getAccepted: db.prepare(`
    SELECT CASE WHEN from_user = ? THEN to_user ELSE from_user END AS friend
    FROM friends
    WHERE (from_user = ? OR to_user = ?) AND status = 'accepted'
  `),
  getIncoming: db.prepare(`
    SELECT from_user AS requester FROM friends
    WHERE to_user = ? AND status = 'pending'
  `),
  getOutgoing: db.prepare(`
    SELECT to_user AS target FROM friends
    WHERE from_user = ? AND status = 'pending'
  `),
  insertAccepted: db.prepare(`
    INSERT OR IGNORE INTO friends (from_user, to_user, status, created_at) VALUES (?, ?, 'accepted', ?)
  `),
};

// ─── ROOM QUERIES ─────────────────────────────────────────────────────────────

const roomQueries = {
  create: db.prepare('INSERT INTO rooms (code, name, owner, color) VALUES (?, ?, ?, ?)'),
  findByCode: db.prepare('SELECT * FROM rooms WHERE code = ?'),
  codeExists: db.prepare('SELECT 1 FROM rooms WHERE code = ?'),
  addMember: db.prepare(`
    INSERT OR IGNORE INTO room_members (room_code, username, joined_at) VALUES (?, ?, ?)
  `),
  getMember: db.prepare('SELECT * FROM room_members WHERE room_code = ? AND username = ? COLLATE NOCASE'),
  getMembers: db.prepare('SELECT username, joined_at FROM room_members WHERE room_code = ?'),
  getUserRooms: db.prepare(`
    SELECT r.*, COUNT(rm2.username) AS member_count
    FROM rooms r
    JOIN room_members rm ON rm.room_code = r.code AND rm.username = ? COLLATE NOCASE
    JOIN room_members rm2 ON rm2.room_code = r.code
    GROUP BY r.code
    ORDER BY r.created_at DESC
  `),
  setColor: db.prepare('UPDATE rooms SET color = ? WHERE code = ?'),
  getMembersExcept: db.prepare('SELECT username FROM room_members WHERE room_code = ? AND username != ? COLLATE NOCASE'),
};

// ─── DAILY PHOTO QUERIES ───────────────────────────────────────────────────────

const dailyPhotoQueries = {
  insert: db.prepare('INSERT INTO daily_photos (room_code, username, photo_url, taken_at, day_date) VALUES (?, ?, ?, ?, ?)'),
  getForRoomAndDay: db.prepare('SELECT * FROM daily_photos WHERE room_code = ? AND day_date = ? ORDER BY taken_at ASC'),
  getForUserToday: db.prepare(`
    SELECT dp.* FROM daily_photos dp
    JOIN room_members rm ON rm.room_code = dp.room_code AND rm.username = ?
    WHERE dp.day_date = ?
    ORDER BY dp.taken_at DESC
  `),
};

// ─── MESSAGE QUERIES ──────────────────────────────────────────────────────────

const messageQueries = {
  insert: db.prepare('INSERT INTO messages (room_code, sender, text, sent_at) VALUES (?, ?, ?, ?)'),
  // Only get messages after the user's join time
  getForUser: db.prepare(`
    SELECT m.id, m.sender, m.text, m.sent_at
    FROM messages m
    JOIN room_members rm ON rm.room_code = m.room_code
      AND rm.username = ? COLLATE NOCASE
      AND m.sent_at >= rm.joined_at
    WHERE m.room_code = ?
    ORDER BY m.sent_at ASC
  `),
};

// ─── HELPER: generate unique room code ───────────────────────────────────────

function generateRoomCode() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let code;
  do {
    code = Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  } while (roomQueries.codeExists.get(code));
  return code;
}

module.exports = {
  db,
  userQueries,
  friendQueries,
  roomQueries,
  messageQueries,
  dailyPhotoQueries,
  generateRoomCode,
};