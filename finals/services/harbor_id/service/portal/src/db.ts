import { DatabaseSync } from 'node:sqlite';
import { writeFileSync, existsSync } from 'fs';
import { randomBytes } from 'crypto';
import path from 'path';

const DATA_DIR = process.env.DATA_DIR ?? '/data';
const DB_PATH = path.join(DATA_DIR, 'portal.db');

export function initDb(): DatabaseSync {
  const db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS portal_users (
      id TEXT PRIMARY KEY,
      idp_sub TEXT,
      idp_iss TEXT,
      email TEXT NOT NULL,
      username TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS portal_crews (
      portal_user_id TEXT NOT NULL REFERENCES portal_users(id),
      crew_name TEXT NOT NULL,
      joined_at INTEGER NOT NULL,
      PRIMARY KEY (portal_user_id, crew_name)
    );

    CREATE TABLE IF NOT EXISTS crew_notes (
      id TEXT PRIMARY KEY,
      crew_name TEXT NOT NULL,
      author_username TEXT NOT NULL,
      text TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS portal_sessions (
      token TEXT PRIMARY KEY,
      portal_user_id TEXT NOT NULL REFERENCES portal_users(id),
      expires_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_portal_users_sub ON portal_users(idp_sub, idp_iss);
    CREATE INDEX IF NOT EXISTS idx_portal_users_email ON portal_users(email);
    CREATE INDEX IF NOT EXISTS idx_crew_notes_crew ON crew_notes(crew_name);
  `);

  setInterval(() => {
    const now = Date.now();
    db.prepare('DELETE FROM portal_sessions WHERE expires_at < ?').run(now);
    // prune notes older than 30 min
    db.prepare('DELETE FROM crew_notes WHERE created_at < ?').run(now - 30 * 60 * 1000);
  }, 300_000);

  return db;
}

export function getPortalUser(
  req: { headers: { authorization?: string } },
  db: DatabaseSync
): { id: string; username: string; email: string } | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const row = db.prepare(
    'SELECT pu.id, pu.username, pu.email FROM portal_sessions ps JOIN portal_users pu ON pu.id = ps.portal_user_id WHERE ps.token = ? AND ps.expires_at > ?'
  ).get(token, Date.now()) as { id: string; username: string; email: string } | undefined;
  return row ?? null;
}
