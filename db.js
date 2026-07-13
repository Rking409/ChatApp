const { Pool } = require('pg');
const crypto = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
});

// ─── QUERY HELPERS ─────────────────────────────────────────────────────────────

async function get(query, params = []) {
  const result = await pool.query(query, params);
  return result.rows[0] || null;
}

async function all(query, params = []) {
  const result = await pool.query(query, params);
  return result.rows;
}

async function run(query, params = []) {
  return await pool.query(query, params);
}

// ─── SCHEMA INITIALIZATION ─────────────────────────────────────────────────────

async function initSchema() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      username   TEXT NOT NULL,
      password   TEXT NOT NULL,
      google_id  TEXT,
      avatar_url TEXT,
      created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)
    )
  `);
  // Case-insensitive unique index on username
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users(LOWER(username))`);
  // Partial unique index for google_id (allows multiple NULLs)
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id) WHERE google_id IS NOT NULL`);

  await run(`
    CREATE TABLE IF NOT EXISTS friends (
      id         SERIAL PRIMARY KEY,
      from_user  TEXT NOT NULL,
      to_user    TEXT NOT NULL,
      status     TEXT NOT NULL DEFAULT 'pending',
      created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)
    )
  `);
  await run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_friends_pair ON friends(LOWER(from_user), LOWER(to_user))`);

  await run(`
    CREATE TABLE IF NOT EXISTS rooms (
      id         SERIAL PRIMARY KEY,
      code       TEXT NOT NULL UNIQUE,
      name       TEXT NOT NULL,
      owner      TEXT NOT NULL,
      color      TEXT NOT NULL DEFAULT '#3B82F6',
      created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS room_members (
      id           SERIAL PRIMARY KEY,
      room_code    TEXT NOT NULL,
      username     TEXT NOT NULL,
      joined_at    BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000),
      last_read_at BIGINT NOT NULL DEFAULT 0,
      UNIQUE(room_code, username)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS messages (
      id        SERIAL PRIMARY KEY,
      room_code TEXT NOT NULL,
      sender    TEXT NOT NULL,
      text      TEXT NOT NULL,
      sent_at   BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000),
      edited    INTEGER NOT NULL DEFAULT 0,
      deleted   INTEGER NOT NULL DEFAULT 0,
      encrypted INTEGER NOT NULL DEFAULT 0,
      enc_iv    TEXT
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_code, sent_at)`);

  await run(`
    CREATE TABLE IF NOT EXISTS message_reactions (
      id         SERIAL PRIMARY KEY,
      message_id INTEGER NOT NULL,
      room_code  TEXT NOT NULL,
      username   TEXT NOT NULL,
      emoji      TEXT NOT NULL,
      created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000),
      UNIQUE(message_id, username, emoji)
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_reactions_message ON message_reactions(message_id)`);

  await run(`
    CREATE TABLE IF NOT EXISTS daily_photos (
      id         SERIAL PRIMARY KEY,
      room_code  TEXT NOT NULL,
      username   TEXT NOT NULL,
      photo_url  TEXT NOT NULL,
      taken_at   BIGINT NOT NULL,
      day_date   TEXT NOT NULL,
      encrypted  INTEGER NOT NULL DEFAULT 0,
      enc_iv     TEXT
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS idx_daily_photos_room_day ON daily_photos(room_code, day_date)`);

  await run(`
    CREATE TABLE IF NOT EXISTS user_keys (
      id         SERIAL PRIMARY KEY,
      username   TEXT NOT NULL UNIQUE,
      public_key TEXT NOT NULL,
      updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS room_keys (
      id             SERIAL PRIMARY KEY,
      room_code      TEXT NOT NULL,
      username       TEXT NOT NULL,
      encrypted_key  TEXT NOT NULL,
      UNIQUE(room_code, username)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS transfer_codes (
      code       TEXT PRIMARY KEY,
      token      TEXT,
      created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW()) * 1000)
    )
  `);

  // ─── MIGRATIONS ──────────────────────────────────────────────────────────────

  // Migrate: add columns that may not exist (added after initial schema)
  const userCols = await all(`SELECT column_name FROM information_schema.columns WHERE table_name = 'users'`);
  const userColNames = userCols.map(c => c.column_name);
  if (!userColNames.includes('google_id')) {
    await run(`ALTER TABLE users ADD COLUMN google_id TEXT`);
    // Index already created above, but safe to re-run
  }
  if (!userColNames.includes('avatar_url')) {
    await run(`ALTER TABLE users ADD COLUMN avatar_url TEXT`);
  }

  const memberCols = await all(`SELECT column_name FROM information_schema.columns WHERE table_name = 'room_members'`);
  const memberColNames = memberCols.map(c => c.column_name);
  if (!memberColNames.includes('last_read_at')) {
    await run(`ALTER TABLE room_members ADD COLUMN last_read_at BIGINT NOT NULL DEFAULT 0`);
  }

  const msgCols = await all(`SELECT column_name FROM information_schema.columns WHERE table_name = 'messages'`);
  const msgColNames = msgCols.map(c => c.column_name);
  if (!msgColNames.includes('edited')) {
    await run(`ALTER TABLE messages ADD COLUMN edited INTEGER NOT NULL DEFAULT 0`);
  }
  if (!msgColNames.includes('deleted')) {
    await run(`ALTER TABLE messages ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0`);
  }
  if (!msgColNames.includes('encrypted')) {
    await run(`ALTER TABLE messages ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0`);
    await run(`ALTER TABLE messages ADD COLUMN enc_iv TEXT`);
  }

  const photoCols = await all(`SELECT column_name FROM information_schema.columns WHERE table_name = 'daily_photos'`);
  const photoColNames = photoCols.map(c => c.column_name);
  if (!photoColNames.includes('encrypted')) {
    await run(`ALTER TABLE daily_photos ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0`);
    await run(`ALTER TABLE daily_photos ADD COLUMN enc_iv TEXT`);
  }

  const roomCols = await all(`SELECT column_name FROM information_schema.columns WHERE table_name = 'rooms'`);
  const roomColNames = roomCols.map(c => c.column_name);
  if (!roomColNames.includes('color')) {
    await run(`ALTER TABLE rooms ADD COLUMN color TEXT NOT NULL DEFAULT '#3B82F6'`);
  }
}

// ─── USER QUERIES ─────────────────────────────────────────────────────────────

const userQueries = {
  async findByUsername(username) {
    return get(`SELECT * FROM users WHERE LOWER(username) = LOWER($1)`, [username]);
  },
  async create(username, password) {
    await run(`INSERT INTO users (username, password) VALUES ($1, $2)`, [username, password]);
  },
  async exists(username) {
    const row = await get(`SELECT 1 FROM users WHERE LOWER(username) = LOWER($1)`, [username]);
    return !!row;
  },
  async findByGoogleId(googleId) {
    return get(`SELECT * FROM users WHERE google_id = $1`, [googleId]);
  },
  async createWithGoogle(username, password, googleId) {
    await run(`INSERT INTO users (username, password, google_id) VALUES ($1, $2, $3)`, [username, password, googleId]);
  },
  async setAvatarUrl(avatarUrl, username) {
    await run(`UPDATE users SET avatar_url = $1 WHERE LOWER(username) = LOWER($2)`, [avatarUrl, username]);
  },
};

// ─── FRIEND QUERIES ───────────────────────────────────────────────────────────

const friendQueries = {
  async getRelation(user1, user2) {
    return get(`
      SELECT * FROM friends
      WHERE (LOWER(from_user) = LOWER($1) AND LOWER(to_user) = LOWER($2))
         OR (LOWER(from_user) = LOWER($2) AND LOWER(to_user) = LOWER($1))
    `, [user1, user2]);
  },
  async sendRequest(fromUser, toUser) {
    await run(`INSERT INTO friends (from_user, to_user, status) VALUES ($1, $2, 'pending')`, [fromUser, toUser]);
  },
  async updateStatus(status, fromUser, toUser) {
    await run(`UPDATE friends SET status = $1 WHERE LOWER(from_user) = LOWER($2) AND LOWER(to_user) = LOWER($3)`, [status, fromUser, toUser]);
  },
  async getAccepted(username) {
    return all(`
      SELECT CASE WHEN LOWER(from_user) = LOWER($1) THEN to_user ELSE from_user END AS friend
      FROM friends
      WHERE (LOWER(from_user) = LOWER($1) OR LOWER(to_user) = LOWER($1)) AND status = 'accepted'
    `, [username]);
  },
  async getIncoming(username) {
    return all(`
      SELECT from_user AS requester FROM friends
      WHERE LOWER(to_user) = LOWER($1) AND status = 'pending'
    `, [username]);
  },
  async getOutgoing(username) {
    return all(`
      SELECT to_user AS target FROM friends
      WHERE LOWER(from_user) = LOWER($1) AND status = 'pending'
    `, [username]);
  },
  async insertAccepted(user1, user2, createdAt) {
    await run(`
      INSERT INTO friends (from_user, to_user, status, created_at)
      VALUES ($1, $2, 'accepted', $3)
      ON CONFLICT (LOWER(from_user), LOWER(to_user)) DO NOTHING
    `, [user1, user2, createdAt]);
  },
};

// ─── ROOM QUERIES ─────────────────────────────────────────────────────────────

const roomQueries = {
  async create(code, name, owner, color) {
    await run(`INSERT INTO rooms (code, name, owner, color) VALUES ($1, $2, $3, $4)`, [code, name, owner, color]);
  },
  async findByCode(code) {
    return get(`SELECT * FROM rooms WHERE code = $1`, [code]);
  },
  async codeExists(code) {
    const row = await get(`SELECT 1 FROM rooms WHERE code = $1`, [code]);
    return !!row;
  },
  async addMember(roomCode, username, joinedAt) {
    await run(`
      INSERT INTO room_members (room_code, username, joined_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (room_code, username) DO NOTHING
    `, [roomCode, username, joinedAt]);
  },
  async getMember(roomCode, username) {
    return get(`SELECT * FROM room_members WHERE room_code = $1 AND LOWER(username) = LOWER($2)`, [roomCode, username]);
  },
  async getMembers(roomCode) {
    return all(`SELECT username, joined_at FROM room_members WHERE room_code = $1`, [roomCode]);
  },
  async getUserRooms(username) {
    return all(`
      SELECT r.*, COUNT(rm2.username)::int AS member_count
      FROM rooms r
      JOIN room_members rm ON rm.room_code = r.code AND LOWER(rm.username) = LOWER($1)
      JOIN room_members rm2 ON rm2.room_code = r.code
      GROUP BY r.id, r.code, r.name, r.owner, r.color, r.created_at
      ORDER BY r.created_at DESC
    `, [username]);
  },
  async setColor(color, code) {
    await run(`UPDATE rooms SET color = $1 WHERE code = $2`, [color, code]);
  },
  async getMembersExcept(roomCode, username) {
    return all(`SELECT username FROM room_members WHERE room_code = $1 AND LOWER(username) != LOWER($2)`, [roomCode, username]);
  },
};

// ─── DAILY PHOTO QUERIES ───────────────────────────────────────────────────────

const dailyPhotoQueries = {
  async insert(roomCode, username, photoUrl, takenAt, dayDate) {
    await run(`INSERT INTO daily_photos (room_code, username, photo_url, taken_at, day_date) VALUES ($1, $2, $3, $4, $5)`, [roomCode, username, photoUrl, takenAt, dayDate]);
  },
  async insertEncrypted(roomCode, username, photoUrl, takenAt, dayDate, encrypted, encIv) {
    const result = await run(`
      INSERT INTO daily_photos (room_code, username, photo_url, taken_at, day_date, encrypted, enc_iv)
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
    `, [roomCode, username, photoUrl, takenAt, dayDate, encrypted, encIv]);
    return result.rows[0].id;
  },
  async getForRoomAndDay(roomCode, dayDate) {
    return all(`SELECT * FROM daily_photos WHERE room_code = $1 AND day_date = $2 ORDER BY taken_at ASC`, [roomCode, dayDate]);
  },
  async getForUserToday(username, today) {
    return all(`
      SELECT dp.* FROM daily_photos dp
      JOIN room_members rm ON rm.room_code = dp.room_code AND LOWER(rm.username) = LOWER($1)
      WHERE dp.day_date = $2
      ORDER BY dp.taken_at DESC
    `, [username, today]);
  },
};

// ─── MESSAGE QUERIES ──────────────────────────────────────────────────────────

const messageQueries = {
  async insert(roomCode, sender, text, sentAt) {
    const result = await run(`INSERT INTO messages (room_code, sender, text, sent_at) VALUES ($1, $2, $3, $4) RETURNING id`, [roomCode, sender, text, sentAt]);
    return result.rows[0].id;
  },
  async insertEncrypted(roomCode, sender, text, sentAt, encrypted, encIv) {
    const result = await run(`INSERT INTO messages (room_code, sender, text, sent_at, encrypted, enc_iv) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, [roomCode, sender, text, sentAt, encrypted, encIv]);
    return result.rows[0].id;
  },
  async findById(id) {
    return get(`SELECT * FROM messages WHERE id = $1`, [id]);
  },
  async updateText(text, id) {
    await run(`UPDATE messages SET text = $1, edited = 1 WHERE id = $2 AND deleted = 0`, [text, id]);
  },
  async markDeleted(id) {
    await run(`UPDATE messages SET deleted = 1 WHERE id = $1`, [id]);
  },
  async getForUser(username, roomCode) {
    return all(`
      SELECT m.id, m.sender, m.text, m.sent_at, m.edited, m.deleted, m.encrypted, m.enc_iv
      FROM messages m
      JOIN room_members rm ON rm.room_code = m.room_code
        AND LOWER(rm.username) = LOWER($1) AND m.sent_at >= rm.joined_at
      WHERE m.room_code = $2 AND m.deleted = 0
      ORDER BY m.sent_at ASC
    `, [username, roomCode]);
  },
  async toggleReaction(messageId, roomCode, username, emoji) {
    await run(`
      INSERT INTO message_reactions (message_id, room_code, username, emoji)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (message_id, username, emoji) DO NOTHING
    `, [messageId, roomCode, username, emoji]);
  },
  async removeReaction(messageId, username, emoji) {
    await run(`DELETE FROM message_reactions WHERE message_id = $1 AND LOWER(username) = LOWER($2) AND emoji = $3`, [messageId, username, emoji]);
  },
  async getReactions(messageId) {
    return all(`SELECT username, emoji FROM message_reactions WHERE message_id = $1 ORDER BY created_at ASC`, [messageId]);
  },
  async getReactionsForMessages(roomCode) {
    return all(`
      SELECT message_id, username, emoji FROM message_reactions
      WHERE message_id IN (SELECT id FROM messages WHERE room_code = $1)
      ORDER BY created_at ASC
    `, [roomCode]);
  },
  async markRead(timestamp, roomCode, username) {
    await run(`UPDATE room_members SET last_read_at = $1 WHERE room_code = $2 AND LOWER(username) = LOWER($3)`, [timestamp, roomCode, username]);
  },
  async getUnreadCount(username, roomCode) {
    return get(`
      SELECT COUNT(*)::int AS count FROM messages m
      JOIN room_members rm ON rm.room_code = m.room_code
        AND LOWER(rm.username) = LOWER($1) AND m.sent_at > rm.last_read_at
      WHERE m.room_code = $2 AND m.deleted = 0
    `, [username, roomCode]);
  },
};

// ─── KEY QUERIES ───────────────────────────────────────────────────────────────

const keyQueries = {
  async setPublicKey(username, publicKey, updatedAt) {
    await run(`
      INSERT INTO user_keys (username, public_key, updated_at)
      VALUES ($1, $2, $3)
      ON CONFLICT (username) DO UPDATE SET public_key = $2, updated_at = $3
    `, [username, publicKey, updatedAt]);
  },
  async getPublicKey(username) {
    return get(`SELECT public_key FROM user_keys WHERE LOWER(username) = LOWER($1)`, [username]);
  },
  async storeRoomKey(roomCode, username, encryptedKey) {
    await run(`
      INSERT INTO room_keys (room_code, username, encrypted_key)
      VALUES ($1, $2, $3)
      ON CONFLICT (room_code, username) DO UPDATE SET encrypted_key = $3
    `, [roomCode, username, encryptedKey]);
  },
  async getRoomKey(roomCode, username) {
    return get(`SELECT encrypted_key FROM room_keys WHERE room_code = $1 AND LOWER(username) = LOWER($2)`, [roomCode, username]);
  },
  async getRoomKeys(roomCode) {
    return all(`SELECT username, encrypted_key FROM room_keys WHERE room_code = $1`, [roomCode]);
  },
  async deleteRoomKeys(roomCode) {
    await run(`DELETE FROM room_keys WHERE room_code = $1`, [roomCode]);
  },
};

// ─── TRANSFER CODE QUERIES ─────────────────────────────────────────────────────

const transferQueries = {
  async insert(code) {
    await run(`INSERT INTO transfer_codes (code) VALUES ($1)`, [code]);
  },
  async claim(code, token) {
    await run(`UPDATE transfer_codes SET token = $1 WHERE code = $2 AND token IS NULL`, [token, code]);
  },
  async getToken(code) {
    return get(`SELECT token FROM transfer_codes WHERE code = $1 AND created_at > (EXTRACT(EPOCH FROM NOW()) * 1000 - 120000)`, [code]);
  },
  async cleanup() {
    await run(`DELETE FROM transfer_codes WHERE created_at < (EXTRACT(EPOCH FROM NOW()) * 1000 - 120000)`);
  },
};

// ─── ADMIN QUERIES ─────────────────────────────────────────────────────────────

const adminQueries = {
  async getAllUsers() {
    return all(`SELECT id, username, google_id, avatar_url, created_at FROM users ORDER BY created_at DESC`);
  },
  async getAllRooms() {
    return all(`SELECT * FROM rooms ORDER BY created_at DESC`);
  },
  async getAllMembers() {
    return all(`SELECT * FROM room_members ORDER BY room_code, username`);
  },
  async getAllFriends() {
    return all(`SELECT * FROM friends ORDER BY created_at DESC`);
  },
  async getAllMessages() {
    return all(`
      SELECT m.id, m.room_code, m.sender, m.text, m.sent_at, m.edited, m.deleted, m.encrypted, m.enc_iv
      FROM messages m ORDER BY m.sent_at DESC LIMIT 2000
    `);
  },
  async getAllPhotos() {
    return all(`SELECT * FROM daily_photos ORDER BY taken_at DESC LIMIT 500`);
  },
  async countUsers() {
    return get(`SELECT COUNT(*)::int AS count FROM users`);
  },
  async countRooms() {
    return get(`SELECT COUNT(*)::int AS count FROM rooms`);
  },
  async countMessages() {
    return get(`SELECT COUNT(*)::int AS count FROM messages WHERE deleted = 0`);
  },
  async countPhotos() {
    return get(`SELECT COUNT(*)::int AS count FROM daily_photos`);
  },
};

// ─── HELPER: generate unique room code ───────────────────────────────────────

async function generateRoomCode() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let code;
  do {
    code = Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
  } while (await roomQueries.codeExists(code));
  return code;
}

// ─── EXPORTS ──────────────────────────────────────────────────────────────────

module.exports = {
  pool,
  initSchema,
  userQueries,
  friendQueries,
  roomQueries,
  messageQueries,
  dailyPhotoQueries,
  keyQueries,
  transferQueries,
  adminQueries,
  generateRoomCode,
};
