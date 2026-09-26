#!/bin/bash
set -e

export PGDATA=/var/lib/postgresql/data
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  initdb -D "$PGDATA" >/dev/null
fi
pg_ctl -D "$PGDATA" -o "-c listen_addresses=127.0.0.1" -w start >/dev/null

psql -v ON_ERROR_STOP=1 -c "SELECT 1 FROM pg_database WHERE datname='formwork'" | grep -q 1 \
  || createdb formwork

psql -v ON_ERROR_STOP=1 -d formwork -f /app/deploy/00_roles.sql

ANCHOR="anchor_$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
sed "s/__ANCHOR__/${ANCHOR}/g" /app/deploy/10_signer.sql.tmpl > /tmp/signer.sql
psql -v ON_ERROR_STOP=1 -d formwork -f /tmp/signer.sql
shred -u /tmp/signer.sql 2>/dev/null || rm -f /tmp/signer.sql
unset ANCHOR

FLAG="${FLAG:-H7CTF{local_test_flag}}"
psql -v ON_ERROR_STOP=1 -d formwork \
  -c "INSERT INTO vault(team, license_key) VALUES ('workspace', \$fw\$${FLAG}\$fw\$) ON CONFLICT (team) DO UPDATE SET license_key=EXCLUDED.license_key"
psql -v ON_ERROR_STOP=1 -d formwork -c "REVOKE SELECT ON vault FROM app"
unset FLAG

export DATABASE_URL="postgres://app:app@127.0.0.1:5432/formwork"
export PORT="${PORT:-8080}"
exec /app/formwork
