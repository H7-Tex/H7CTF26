import type { FastifyInstance } from 'fastify';
import type { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'crypto';
import { getPortalUser } from '../db.ts';

export default async function crewRoutes(app: FastifyInstance, db: DatabaseSync) {
  // show the crew board for the logged-in user
  app.get('/crew/board', async (req, reply) => {
    const user = getPortalUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-BOARD-01: authentication required' });

    const memberships = db.prepare(
      'SELECT crew_name FROM portal_crews WHERE portal_user_id = ? ORDER BY joined_at ASC'
    ).all(user.id) as { crew_name: string }[];

    const result = [];
    for (const { crew_name } of memberships) {
      const notes = db.prepare(
        'SELECT id, author_username, text, created_at FROM crew_notes WHERE crew_name = ? ORDER BY created_at ASC'
      ).all(crew_name) as { id: string; author_username: string; text: string; created_at: number }[];
      result.push({
        crew: crew_name,
        notes: notes.map(n => ({ id: n.id, author: n.author_username, text: n.text, at: n.created_at }))
      });
    }
    return { boards: result };
  });

  // post a note to a crew the user belongs to
  app.post('/crew/notes', async (req, reply) => {
    const user = getPortalUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-NOTES-01: authentication required' });

    const body = req.body as { crew_name?: string; text?: string };
    if (!body.crew_name || !body.text) {
      return reply.code(400).send({ error: 'HARBORID-NOTES-02: crew_name and text required' });
    }

    const membership = db.prepare(
      'SELECT 1 FROM portal_crews WHERE portal_user_id = ? AND crew_name = ?'
    ).get(user.id, body.crew_name);
    if (!membership) return reply.code(403).send({ error: 'HARBORID-NOTES-03: not a crew member' });

    const id = randomUUID();
    db.prepare(
      'INSERT INTO crew_notes (id, crew_name, author_username, text, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(id, body.crew_name, user.username, body.text, Date.now());

    return { ok: true, id };
  });

  // list crew memberships for this user
  app.get('/crew/memberships', async (req, reply) => {
    const user = getPortalUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-MEM-01: authentication required' });
    const rows = db.prepare(
      'SELECT crew_name FROM portal_crews WHERE portal_user_id = ? ORDER BY crew_name ASC'
    ).all(user.id) as { crew_name: string }[];
    return { crews: rows.map(r => r.crew_name) };
  });
}
