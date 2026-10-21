import Fastify from 'fastify';
import { initDb } from './db.ts';
import { initOidcKeys } from './routes/oidc.ts';
import accountRoutes from './routes/account.ts';
import webauthnRoutes from './routes/webauthn.ts';
import oidcRoutes from './routes/oidc.ts';

const PORT = parseInt(process.env.PORT ?? '7001');

const app = Fastify({ logger: { level: 'warn' } });

// parse JSON bodies
app.addContentTypeParser('application/json', { parseAs: 'string' }, function (req, body, done) {
  try { done(null, JSON.parse(body as string)); }
  catch (err) { done(err as Error, undefined); }
});

async function start() {
  const db = initDb();
  await initOidcKeys();

  await accountRoutes(app, db);
  await webauthnRoutes(app, db);
  await oidcRoutes(app, db);

  app.get('/health', async () => ({ ok: true }));

  await app.listen({ port: PORT, host: '0.0.0.0' });
  console.log(`harbor-idp listening on ${PORT}`);
}

start().catch(err => { console.error(err); process.exit(1); });
