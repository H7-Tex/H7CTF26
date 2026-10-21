import type { FastifyInstance } from 'fastify';
import type { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID } from 'crypto';
import {
  coseKeyToNodeKey, spkiToKeyObj, verifyES256,
  parseAttestationObject, verifyClientDataCreate, verifyClientDataGet, verifyAuthData
} from '../crypto.ts';
import { getSessionUser } from './account.ts';

const RP_ID = 'harbor.city';
const RP_NAME = 'Harbor ID';

export default async function webauthnRoutes(app: FastifyInstance, db: DatabaseSync) {
  // begin registration: client authenticated (has a session), calls this to add a passkey
  app.post('/webauthn/register/begin', async (req, reply) => {
    const user = getSessionUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-WABEG-01: authentication required' });
    const challenge = randomBytes(32).toString('base64url');
    const id = randomUUID();
    const expires = Date.now() + 120_000;
    db.prepare(
      'INSERT INTO challenges (id, user_id, username, challenge, type, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(id, user.id, user.username, challenge, 'registration', expires);
    return {
      challenge,
      sessionId: id,
      rp: { id: RP_ID, name: RP_NAME },
      user: {
        id: Buffer.from(user.id).toString('base64url'),
        name: user.username,
        displayName: user.username
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000,
      attestation: 'none'
    };
  });

  // finish registration
  // BUG V2 (store B): user_id is taken from req.body instead of the stored challenge record.
  // correct patch: use chal.user_id instead of body.user_id
  app.post('/webauthn/register/finish', async (req, reply) => {
    const body = req.body as {
      sessionId?: string;
      user_id?: string;          // BUG: should come from stored challenge, not client
      response?: {
        id?: string;
        type?: string;
        response?: {
          clientDataJSON?: string;
          attestationObject?: string;
        }
      }
    };

    if (!body.sessionId || !body.response?.response?.clientDataJSON || !body.response?.response?.attestationObject) {
      return reply.code(400).send({ error: 'HARBORID-WAFREG-01: missing fields' });
    }

    const chal = db.prepare(
      'SELECT * FROM challenges WHERE id = ? AND type = ? AND expires_at > ?'
    ).get(body.sessionId, 'registration', Date.now()) as {
      id: string; user_id: string; challenge: string
    } | undefined;
    if (!chal) return reply.code(400).send({ error: 'HARBORID-WAFREG-02: session not found or expired' });

    // BUG: use body.user_id (attacker controlled) instead of chal.user_id
    const userId = body.user_id ?? chal.user_id;

    try {
      verifyClientDataCreate(body.response.response.clientDataJSON!, chal.challenge);
    } catch (e: unknown) {
      return reply.code(400).send({ error: (e as Error).message });
    }

    let authData: Buffer, coseKey: Map<number, Uint8Array>, credId: Buffer;
    try {
      ({ authData, coseKey, credId } = parseAttestationObject(body.response.response.attestationObject!));
    } catch (e: unknown) {
      return reply.code(400).send({ error: (e as Error).message });
    }

    let spki: string;
    try {
      ({ spki } = coseKeyToNodeKey(coseKey));
    } catch (e: unknown) {
      return reply.code(400).send({ error: (e as Error).message });
    }

    const credIdStr = body.response.id ?? Buffer.from(credId).toString('base64url');

    db.prepare('DELETE FROM challenges WHERE id = ?').run(body.sessionId);

    try {
      db.prepare(
        'INSERT INTO credentials (cred_id, user_id, public_key_spki, algorithm, sign_count, created_at) VALUES (?, ?, ?, -7, 0, ?)'
      ).run(credIdStr, userId, spki, Date.now());
    } catch {
      return reply.code(409).send({ error: 'HARBORID-WAFREG-03: credential already registered' });
    }

    // issue a session token for the (possibly attacker-controlled) userId
    const target = db.prepare('SELECT id, username FROM users WHERE id = ?').get(userId) as {
      id: string; username: string
    } | undefined;
    if (!target) return reply.code(400).send({ error: 'HARBORID-WAFREG-04: user not found' });

    const sessionToken = randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(
      sessionToken, target.id, Date.now() + 86_400_000
    );

    return { ok: true, token: sessionToken, username: target.username };
  });

  // begin login: optionally takes a username (for username-first flow)
  // usernameless flow: no username, empty allowCredentials
  app.post('/webauthn/login/begin', async (req, reply) => {
    const body = req.body as { username?: string };
    const challenge = randomBytes(32).toString('base64url');
    const id = randomUUID();
    const expires = Date.now() + 120_000;

    let allowCredentials: { type: string; id: string }[] = [];
    let userId: string | null = null;

    if (body.username) {
      const user = db.prepare('SELECT id FROM users WHERE username = ?').get(body.username) as { id: string } | undefined;
      if (user) {
        userId = user.id;
        const creds = db.prepare('SELECT cred_id FROM credentials WHERE user_id = ?').all(userId) as { cred_id: string }[];
        allowCredentials = creds.map(c => ({ type: 'public-key', id: c.cred_id }));
      }
    }
    // for usernameless, allowCredentials stays empty

    db.prepare(
      'INSERT INTO challenges (id, user_id, username, challenge, type, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(id, userId, body.username ?? null, challenge, 'assertion', expires);

    return {
      challenge,
      sessionId: id,
      rpId: RP_ID,
      allowCredentials,
      userVerification: 'required',
      timeout: 60000
    };
  });

  // finish login
  // BUG V1 (store B): userHandle from response is used as the logged-in user identity
  // without checking that the credential's owner matches userHandle.
  // correct patch: verify cred.user_id === userHandle before accepting the login
  app.post('/webauthn/login/finish', async (req, reply) => {
    const body = req.body as {
      sessionId?: string;
      response?: {
        id?: string;
        type?: string;
        response?: {
          authenticatorData?: string;
          clientDataJSON?: string;
          signature?: string;
          userHandle?: string;   // BUG: trusted directly
        }
      }
    };

    if (!body.sessionId || !body.response?.response?.authenticatorData ||
        !body.response?.response?.clientDataJSON || !body.response?.response?.signature) {
      return reply.code(400).send({ error: 'HARBORID-WALOG-01: missing fields' });
    }

    const chal = db.prepare(
      'SELECT * FROM challenges WHERE id = ? AND type = ? AND expires_at > ?'
    ).get(body.sessionId, 'assertion', Date.now()) as {
      id: string; user_id: string | null; challenge: string
    } | undefined;
    if (!chal) return reply.code(400).send({ error: 'HARBORID-WALOG-02: session not found or expired' });

    const credId = body.response.id ?? '';
    const cred = db.prepare('SELECT * FROM credentials WHERE cred_id = ?').get(credId) as {
      cred_id: string; user_id: string; public_key_spki: string; sign_count: number
    } | undefined;
    if (!cred) return reply.code(400).send({ error: 'HARBORID-WALOG-03: credential not found' });

    const authData = Buffer.from(body.response.response.authenticatorData!, 'base64url');
    try {
      verifyAuthData(authData);
    } catch (e: unknown) {
      return reply.code(400).send({ error: (e as Error).message });
    }

    try {
      verifyClientDataGet(body.response.response.clientDataJSON!, chal.challenge);
    } catch (e: unknown) {
      return reply.code(400).send({ error: (e as Error).message });
    }

    const sigDer = Buffer.from(body.response.response.signature!, 'base64url');
    const clientDataJsonBytes = Buffer.from(body.response.response.clientDataJSON!, 'base64url');
    const keyObj = spkiToKeyObj(cred.public_key_spki);
    if (!verifyES256(keyObj, authData, clientDataJsonBytes, sigDer)) {
      return reply.code(400).send({ error: 'HARBORID-WALOG-04: signature verification failed' });
    }

    // BUG V1: determine the logged-in user from userHandle (not from the credential's owner).
    // an attacker can use their own credential with a victim's userHandle and log in as the victim.
    const userHandle = body.response.response.userHandle;
    let userId: string;
    if (userHandle) {
      // decode userHandle: it is base64url of the user's sub (UUID)
      const decoded = Buffer.from(userHandle, 'base64url').toString();
      // BUG: no check that decoded === cred.user_id
      userId = decoded;
    } else {
      userId = cred.user_id;
    }

    const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(userId) as {
      id: string; username: string
    } | undefined;
    if (!user) return reply.code(400).send({ error: 'HARBORID-WALOG-05: user not found' });

    db.prepare('DELETE FROM challenges WHERE id = ?').run(body.sessionId);

    const sessionToken = randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(
      sessionToken, user.id, Date.now() + 86_400_000
    );

    return { token: sessionToken, username: user.username };
  });
}
