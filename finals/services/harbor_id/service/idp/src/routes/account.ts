import type { FastifyInstance } from 'fastify';
import type { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID } from 'crypto';

export default async function accountRoutes(app: FastifyInstance, db: DatabaseSync) {
  // register a new user (username + email + break_glass_note)
  app.post('/register', async (req, reply) => {
    const body = req.body as { username?: string; email?: string; break_glass_note?: string };
    if (!body.username || !body.email) {
      return reply.code(400).send({ error: 'HARBORID-REG-01: username and email required' });
    }
    const id = randomUUID();
    const now = Date.now();
    try {
      db.prepare(
        'INSERT INTO users (id, username, email, email_verified, break_glass_note, created_at) VALUES (?, ?, ?, 0, ?, ?)'
      ).run(id, body.username, body.email, body.break_glass_note ?? '', now);
    } catch {
      return reply.code(409).send({ error: 'HARBORID-REG-02: username already taken' });
    }
    // bootstrap token: one-time session valid for 5 min, used to call register/begin
    const bootstrapToken = randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(
      bootstrapToken, id, now + 300_000
    );
    return reply.code(201).send({ id, username: body.username, bootstrap_token: bootstrapToken });
  });

  // get own account info (requires session)
  app.get('/account', async (req, reply) => {
    const user = getSessionUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-ACCT-01: authentication required' });
    const crews = db.prepare(
      'SELECT c.id, c.name FROM crews c JOIN crew_members cm ON cm.crew_id = c.id WHERE cm.user_id = ?'
    ).all(user.id) as { id: string; name: string }[];
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      email_verified: user.email_verified === 1,
      break_glass_note: user.break_glass_note,
      crews: crews.map(c => ({ id: c.id, name: c.name }))
    };
  });

  // update email - no verification (intentionally, for game mechanics)
  app.patch('/account/email', async (req, reply) => {
    const user = getSessionUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-ACCT-02: authentication required' });
    const body = req.body as { email?: string };
    if (!body.email) return reply.code(400).send({ error: 'HARBORID-ACCT-03: email required' });
    // email_verified stays 0: we note it may not match the inbox
    db.prepare('UPDATE users SET email = ?, email_verified = 0 WHERE id = ?').run(body.email, user.id);
    return { ok: true };
  });

  // crew management
  app.post('/crews', async (req, reply) => {
    const user = getSessionUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-CREW-01: authentication required' });
    const body = req.body as { name?: string };
    if (!body.name) return reply.code(400).send({ error: 'HARBORID-CREW-02: name required' });
    const id = randomUUID();
    const now = Date.now();
    try {
      db.prepare('INSERT INTO crews (id, name, created_at) VALUES (?, ?, ?)').run(id, body.name, now);
      db.prepare('INSERT INTO crew_members (crew_id, user_id) VALUES (?, ?)').run(id, user.id);
    } catch {
      return reply.code(409).send({ error: 'HARBORID-CREW-03: crew name taken' });
    }
    return reply.code(201).send({ id, name: body.name });
  });

  app.post('/crews/:crewId/members', async (req, reply) => {
    const user = getSessionUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-CREW-04: authentication required' });
    const { crewId } = req.params as { crewId: string };
    const body = req.body as { username?: string };
    if (!body.username) return reply.code(400).send({ error: 'HARBORID-CREW-05: username required' });
    const target = db.prepare('SELECT id FROM users WHERE username = ?').get(body.username) as { id: string } | undefined;
    if (!target) return reply.code(404).send({ error: 'HARBORID-CREW-06: user not found' });
    const crew = db.prepare('SELECT id FROM crews WHERE id = ?').get(crewId) as { id: string } | undefined;
    if (!crew) return reply.code(404).send({ error: 'HARBORID-CREW-07: crew not found' });
    try {
      db.prepare('INSERT INTO crew_members (crew_id, user_id) VALUES (?, ?)').run(crewId, target.id);
    } catch {
      return reply.code(409).send({ error: 'HARBORID-CREW-08: already a member' });
    }
    return { ok: true };
  });

  app.get('/crews', async (req, reply) => {
    const rows = db.prepare(
      'SELECT c.id, c.name, u.username FROM crews c JOIN crew_members cm ON cm.crew_id = c.id JOIN users u ON u.id = cm.user_id ORDER BY c.name, u.username'
    ).all() as { id: string; name: string; username: string }[];
    const map = new Map<string, { id: string; name: string; members: string[] }>();
    for (const r of rows) {
      if (!map.has(r.id)) map.set(r.id, { id: r.id, name: r.name, members: [] });
      map.get(r.id)!.members.push(r.username);
    }
    return { crews: [...map.values()] };
  });

  // public directory: usernames, emails (like a company directory), and their crews
  app.get('/directory', async (_req, reply) => {
    const users = db.prepare('SELECT id, username, email FROM users ORDER BY username').all() as {
      id: string; username: string; email: string
    }[];
    const result = users.map(u => {
      const crews = db.prepare(
        'SELECT c.id, c.name FROM crews c JOIN crew_members cm ON cm.crew_id = c.id WHERE cm.user_id = ?'
      ).all(u.id) as { id: string; name: string }[];
      return { username: u.username, email: u.email, crews: crews.map(c => c.name) };
    });
    return { users: result };
  });

  // webfinger for user handle discovery
  app.get('/.well-known/webfinger', async (req, reply) => {
    const resource = (req.query as { resource?: string }).resource ?? '';
    const match = resource.match(/^acct:([^@]+)@/);
    if (!match) return reply.code(400).send({ error: 'HARBORID-WF-01: invalid resource' });
    const user = db.prepare('SELECT id, username FROM users WHERE username = ?').get(match[1]) as {
      id: string; username: string
    } | undefined;
    if (!user) return reply.code(404).send({ error: 'HARBORID-WF-02: not found' });
    return { subject: resource, sub: user.id };
  });

  // user device keys (for jku trust - V3 stretch, but havoc uses it)
  app.get('/u/:username/jwks.json', async (req, reply) => {
    const { username } = req.params as { username: string };
    const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username) as { id: string } | undefined;
    if (!user) return reply.code(404).send({ error: 'HARBORID-DEVK-01: user not found' });
    const keys = db.prepare('SELECT jwks_json FROM user_device_keys WHERE user_id = ?').all(user.id) as { jwks_json: string }[];
    const jwks = keys.flatMap(k => {
      try { return JSON.parse(k.jwks_json).keys ?? []; } catch { return []; }
    });
    reply.header('Content-Type', 'application/json');
    return { keys: jwks };
  });

  app.post('/u/:username/keys', async (req, reply) => {
    const user = getSessionUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-DEVK-02: authentication required' });
    const { username } = req.params as { username: string };
    if (user.username !== username) return reply.code(403).send({ error: 'HARBORID-DEVK-03: forbidden' });
    const body = req.body as { kid?: string; jwks?: object };
    if (!body.kid || !body.jwks) return reply.code(400).send({ error: 'HARBORID-DEVK-04: kid and jwks required' });
    const id = randomUUID();
    const now = Date.now();
    db.prepare(
      'INSERT OR REPLACE INTO user_device_keys (id, user_id, kid, jwks_json, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(id, user.id, body.kid, JSON.stringify(body.jwks), now);
    return { ok: true, kid: body.kid };
  });
}

export function getSessionUser(
  req: { headers: { authorization?: string } },
  db: DatabaseSync
): { id: string; username: string; email: string; email_verified: number; break_glass_note: string } | null {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const session = db.prepare('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?').get(token, Date.now()) as { user_id: string } | undefined;
  if (!session) return null;
  return db.prepare('SELECT id, username, email, email_verified, break_glass_note FROM users WHERE id = ?').get(session.user_id) as { id: string; username: string; email: string; email_verified: number; break_glass_note: string } | null;
}
