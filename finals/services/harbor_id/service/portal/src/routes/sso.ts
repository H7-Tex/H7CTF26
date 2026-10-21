import type { FastifyInstance } from 'fastify';
import type { DatabaseSync } from 'node:sqlite';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import { randomBytes, randomUUID } from 'crypto';

const IDP_URL = process.env.IDP_URL ?? 'http://harbor-idp:7001';
const IDP_ISSUER = process.env.IDP_ISSUER ?? 'http://harbor-idp:7001';

// lazy-init the JWKS fetcher
let jwksUrl: URL;

function getJwks() {
  if (!jwksUrl) jwksUrl = new URL(`${IDP_URL}/.well-known/jwks.json`);
  return createRemoteJWKSet(jwksUrl);
}

export default async function ssoRoutes(app: FastifyInstance, db: DatabaseSync) {
  // receive an id_token from the IdP and create/restore a Portal session
  // BUG V1 (store A): account lookup uses the `email` claim instead of `(iss, sub)`.
  // correct patch: look up by (idp_iss, idp_sub) - the sub field uniquely identifies a user at an IdP.
  // an attacker can register a new IdP account with the victim's email and log in as the victim in the Portal.
  app.post('/crew/session', async (req, reply) => {
    const body = req.body as { id_token?: string };
    if (!body.id_token) return reply.code(400).send({ error: 'HARBORID-SSO-01: id_token required' });

    let payload: Record<string, unknown>;
    try {
      const result = await jwtVerify(body.id_token, getJwks(), {
        issuer: IDP_ISSUER,
        audience: 'harbor-portal'
      });
      payload = result.payload as Record<string, unknown>;
    } catch (e: unknown) {
      return reply.code(401).send({ error: `HARBORID-SSO-02: token validation failed: ${(e as Error).message}` });
    }

    const sub = payload.sub as string;
    const email = payload.email as string;
    const username = (payload.username as string) ?? email.split('@')[0];
    const crews = Array.isArray(payload.crew) ? (payload.crew as string[]) : (payload.crew ? [payload.crew as string] : []);
    const iss = payload.iss as string;

    // BUG V1: look up by email instead of (iss, sub)
    let portalUser = db.prepare('SELECT id FROM portal_users WHERE email = ?').get(email) as { id: string } | undefined;

    if (!portalUser) {
      const id = randomUUID();
      const now = Date.now();
      db.prepare(
        'INSERT INTO portal_users (id, idp_sub, idp_iss, email, username, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(id, sub, iss, email, username, now);
      portalUser = { id };
    }

    // merge crews: the portal never removes a crew once it has been added
    // (the idp "sometimes omits claims under load")
    for (const crew of crews) {
      const now = Date.now();
      db.prepare('INSERT OR IGNORE INTO portal_crews (portal_user_id, crew_name, joined_at) VALUES (?, ?, ?)').run(
        portalUser.id, crew, now
      );
    }

    const sessionToken = randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO portal_sessions (token, portal_user_id, expires_at) VALUES (?, ?, ?)').run(
      sessionToken, portalUser.id, Date.now() + 86_400_000
    );

    return { token: sessionToken, username };
  });
}
