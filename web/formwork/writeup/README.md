# Formwork - intended solve

## Scenario

Formwork is an Airtable-style low-code base builder. A team creates a Base, adds
Fields (each Field is a real column on a per-base physical table `b_<id>`), enters
Records, and can "seal" the Base. Sealing signs the schema so later drift is
detectable. The signature is produced by a Postgres routine that reads the
workspace license key, folds every field into a rollup, and writes a fingerprint
plus a human readable "components" note back onto the base page.

The per-team flag is the workspace license key. It is injected at boot into
`vault.license_key` and the app database role has `SELECT` on `vault` revoked.
There is no flag file and no flag table the app can read.

## The two SQL surfaces

Two paths build SQL from field identifiers, and only one is safe.

1. Data definition (add / rename / drop field, and the blueprint import) builds
   identifiers with `pgx.Identifier{name}.Sanitize()`. That is a proper quoted
   identifier, not a string context. `RENAME COLUMN "old" TO "new"` cannot be
   broken out of. Hammering the visible field name into `ALTER TABLE` is the
   dead end.

2. The seal routine `compute_fingerprint(baseid)` is a `SECURITY DEFINER`
   PL/pgSQL function owned by `rollup_owner`, the only role allowed to read
   `vault`. It is deployed sealed at instance boot and is not part of the
   handout, so its body has to be inferred from behaviour. It:
   - creates a temp table `_stage(field, frag)`,
   - seeds one row `(<anchor>, <license key>)` where `<anchor>` is a random
     per-instance token,
   - loops `field_meta.col_ident` and for each field runs a dynamic
     `EXECUTE` built by string concatenation into a single quoted literal:
     `'INSERT INTO _stage(field,frag) SELECT ''' || col_ident || ''', md5(frag) FROM _stage WHERE field=''<anchor>'''`,
   - persists `string_agg(DISTINCT field ...)` into `base_rollup.note` and drops
     the temp table.

`col_ident` is the sink. It is concatenated raw into a string literal inside a
definer context, and PL/pgSQL `EXECUTE` runs multiple semicolon separated
statements.

## Why the UI cannot carry the payload

The field editor slugifies a label to `col_ident` (strips quotes and
punctuation), so a payload typed there is destroyed. The bulk blueprint import
(`POST /api/bases/:id/import`) trusts its own export format and writes
`col_ident` verbatim. That is the path that stores an attacker controlled
identifier unchanged.

## Live step (this is required)

The anchor is random per instance and is one of the "components" listed in the
rendered note. So a normal recon seal reveals it:

1. create a base, add any field, seal it,
2. read the components note, take the `anchor_...` token.

A payload that hardcodes an anchor from another instance selects zero rows and
exfiltrates nothing.

## Payload

Store this raw as `col_ident` (no quote doubling: it is stored verbatim and
concatenated directly):

```
', md5(frag) FROM _stage WHERE field='<anchor>'; INSERT INTO _stage(field,frag) SELECT frag, 'x' FROM _stage WHERE field='<anchor>'; --
```

After interpolation the executed string is three statements: the neutered
original, an injected `INSERT` that copies the seed `frag` (the license key)
into `_stage` as a new `field` value, and a comment that swallows the tail.
When the routine then aggregates distinct `field` values into `note`, the
license key rides along.

## Steps

1. Recon seal, read the anchor from the components note.
2. Import a blueprint whose one field has the payload above as `col_ident`.
3. Seal once.
4. Reload the base page. The components note now contains the flag.

`solution/solve.py` performs all four steps and prints the recovered flag.

## Deploy notes

- One per-team pod: Go app plus Postgres 16. `deploy/00_roles.sql` sets up the
  `app` and `rollup_owner` roles and the privilege split. The signer function is
  generated at boot from a template by substituting a fresh anchor, then applied
  as `rollup_owner`; it is intentionally excluded from the handout.
- `entrypoint.sh` writes `$FLAG` into `vault.license_key` once and revokes
  `SELECT` on `vault` from `app`.
- The seal endpoint is rate limited (anti spray only, not the difficulty gate).
- DB state resets on instance restart.
