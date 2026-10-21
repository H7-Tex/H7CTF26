import { DatabaseSync } from 'node:sqlite';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { randomBytes } from 'crypto';
import path from 'path';

const DATA_DIR = process.env.DATA_DIR ?? '/data';
const DB_PATH = path.join(DATA_DIR, 'idp.db');
const KEY_PATH = path.join(DATA_DIR, 'instance.key');

export let instanceKey: string;

function ensureSecrets() {
  if (!existsSync(KEY_PATH)) {
    instanceKey = randomBytes(32).toString('base64url');
    writeFileSync(KEY_PATH, instanceKey, { mode: 0o600 });
  } else {
    instanceKey = readFileSync(KEY_PATH, 'utf8').trim();
  }
}

export function initDb(): DatabaseSync {
  ensureSecrets();
  const db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      email_verified INTEGER NOT NULL DEFAULT 0,
      break_glass_note TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS credentials (
      cred_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      public_key_spki TEXT NOT NULL,
      algorithm INTEGER NOT NULL DEFAULT -7,
      sign_count INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS crews (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS crew_members (
      crew_id TEXT NOT NULL REFERENCES crews(id),
      user_id TEXT NOT NULL REFERENCES users(id),
      PRIMARY KEY (crew_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS challenges (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      username TEXT,
      challenge TEXT NOT NULL,
      type TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_device_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      kid TEXT NOT NULL,
      jwks_json TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      UNIQUE(user_id, kid)
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_creds_user ON credentials(user_id);
    CREATE INDEX IF NOT EXISTS idx_crew_members_crew ON crew_members(crew_id);
    CREATE INDEX IF NOT EXISTS idx_crew_members_user ON crew_members(user_id);
  `);

  // prune expired data every 5 minutes
  setInterval(() => {
    const now = Date.now();
    db.prepare('DELETE FROM challenges WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
  }, 300_000);

  return db;
}
