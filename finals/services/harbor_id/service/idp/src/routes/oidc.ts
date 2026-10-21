import type { FastifyInstance } from 'fastify';
import type { DatabaseSync } from 'node:sqlite';
import { SignJWT, importJWK, generateKeyPair, exportJWK } from 'jose';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { randomUUID } from 'crypto';
import path from 'path';
import { getSessionUser } from './account.ts';

const DATA_DIR = process.env.DATA_DIR ?? '/data';
const KEYS_PATH = path.join(DATA_DIR, 'jwt_keys.json');
const IDP_ISSUER = process.env.IDP_ISSUER ?? 'http://harbor-idp:7001';

// claim allowlist: these come from the real user record, never from the claims parameter value
const USER_SOURCED_CLAIMS = new Set(['sub', 'email', 'email_verified', 'username', 'iss', 'iat', 'exp', 'aud', 'acr']);

let privateKey: CryptoKey;
let publicJwk: object;
let kid: string;

export async function initOidcKeys() {
  if (existsSync(KEYS_PATH)) {
    const saved = JSON.parse(readFileSync(KEYS_PATH, 'utf8'));
    privateKey = await importJWK(saved.private, 'ES256') as CryptoKey;
    publicJwk = saved.public;
    kid = saved.kid;
  } else {
    const { privateKey: priv, publicKey: pub } = await generateKeyPair('ES256');
    kid = randomUUID();
    const privJwk = await exportJWK(priv);
    privJwk.kid = kid;
    privJwk.alg = 'ES256';
    const pubJwk = await exportJWK(pub);
    pubJwk.kid = kid;
    pubJwk.alg = 'ES256';
    pubJwk.use = 'sig';
    publicJwk = pubJwk;
    privateKey = priv as CryptoKey;
    writeFileSync(KEYS_PATH, JSON.stringify({ private: privJwk, public: pubJwk, kid }), { mode: 0o600 });
  }
}

export default async function oidcRoutes(app: FastifyInstance, db: DatabaseSync) {
  // discovery document
  app.get('/.well-known/openid-configuration', async (_req, reply) => {
    reply.header('Content-Type', 'application/json');
    return {
      issuer: IDP_ISSUER,
      authorization_endpoint: `${IDP_ISSUER}/oauth/authorize`,
      token_endpoint: `${IDP_ISSUER}/oauth/token`,
      jwks_uri: `${IDP_ISSUER}/.well-known/jwks.json`,
      userinfo_endpoint: `${IDP_ISSUER}/account`,
      claims_supported: ['sub', 'email', 'email_verified', 'username', 'crew', 'acr'],
      claims_parameter_supported: true,
      scopes_supported: ['openid', 'profile', 'crew'],
      response_types_supported: ['code'],
      id_token_signing_alg_values_supported: ['ES256']
    };
  });

  // JWKS endpoint
  app.get('/.well-known/jwks.json', async (_req, reply) => {
    reply.header('Content-Type', 'application/jwk-set+json');
    return { keys: [publicJwk] };
  });

  // issue an id_token for the authenticated user
  // BUG V2 (store A): the OIDC `claims` request parameter echoes back the requested `value`
  // for any claim not in USER_SOURCED_CLAIMS, without verifying the user actually has that value.
  // correct patch: ignore the `value` field; only use claims parameter as a filter/presence request
  app.get('/account/token', async (req, reply) => {
    const user = getSessionUser(req, db);
    if (!user) return reply.code(401).send({ error: 'HARBORID-TOKEN-01: authentication required' });

    const query = req.query as { nonce?: string; claims?: string };
    const nonce = query.nonce ?? '';

    // parse OIDC claims parameter (optional)
    let requestedClaims: Record<string, { value?: string; values?: string[]; essential?: boolean }> = {};
    if (query.claims) {
      try {
        const parsed = JSON.parse(query.claims);
        requestedClaims = parsed?.id_token ?? {};
      } catch {
        return reply.code(400).send({ error: 'HARBORID-TOKEN-02: invalid claims parameter' });
      }
    }

    // build real crew list
    const crews = db.prepare(
      'SELECT c.name FROM crews c JOIN crew_members cm ON cm.crew_id = c.id WHERE cm.user_id = ?'
    ).all(user.id) as { name: string }[];
    const crewNames = crews.map(c => c.name);

    // start with user's real claims
    const claims: Record<string, unknown> = {
      sub: user.id,
      email: user.email,
      email_verified: user.email_verified === 1,
      username: user.username,
      crew: crewNames,
      acr: 'urn:harbor:passkey'
    };

    // BUG V2: for any requested claim not in USER_SOURCED_CLAIMS,
    // if a `value` is specified, echo it into the token.
    // this lets an attacker request `crew: {value: "Tug-7 Night"}` and get that crew in their token.
    for (const [claimName, opts] of Object.entries(requestedClaims)) {
      if (USER_SOURCED_CLAIMS.has(claimName)) continue;
      if (opts?.value !== undefined) {
        // echo the requested value directly
        claims[claimName] = opts.value;
      }
    }

    const idToken = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', kid })
      .setIssuedAt()
      .setIssuer(IDP_ISSUER)
      .setAudience('harbor-portal')
      .setExpirationTime('1h')
      .sign(privateKey as any);

    return { id_token: idToken };
  });
}
