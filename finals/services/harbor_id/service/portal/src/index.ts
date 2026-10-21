import Fastify from 'fastify';
import { initDb } from './db.ts';
import ssoRoutes from './routes/sso.ts';
import crewRoutes from './routes/crew.ts';

const PORT = parseInt(process.env.PORT ?? '7011');

const app = Fastify({ logger: { level: 'warn' } });

app.addContentTypeParser('application/json', { parseAs: 'string' }, function (req, body, done) {
  try { done(null, JSON.parse(body as string)); }
  catch (err) { done(err as Error, undefined); }
});

async function start() {
  const db = initDb();

  await ssoRoutes(app, db);
  await crewRoutes(app, db);

  app.get('/health', async () => ({ ok: true }));

  await app.listen({ port: PORT, host: '0.0.0.0' });
  console.log(`harbor-portal listening on ${PORT}`);
}

start().catch(err => { console.error(err); process.exit(1); });
