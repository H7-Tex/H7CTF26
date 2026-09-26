# Formwork

Formwork is an internal low-code base builder. You create a Base, add Fields,
enter Records, and can "seal" a Base to sign its schema so later drift is
detectable.

This archive is the application source for reference:

- `src/main.go`, `src/templates.go` - the Go service (net/http + pgx v5).
- `src/go.mod`, `src/go.sum` - modules.
- `src/deploy/00_roles.sql` - database roles and the privilege split.
- `entrypoint.sh`, `Dockerfile` - how an instance boots.

The schema signing routine runs inside Postgres and is deployed sealed with each
instance. It is not part of this archive.

Your instance is live over HTTPS. There is no flag file. Go build something and
seal it.
