# Formwork

**Category:** web  **Difficulty:** hard  **Author:** abu

> Formwork is our internal low-code base builder. Spin up a base, shape its fields, and seal it so the schema gets signed and any later drift shows up.
>
> Read the record no base is supposed to contain.

Handout: `handout/formwork.zip` (Go source, roles SQL, Dockerfile, entrypoint). The signing routine (`challenge/deploy/10_signer.sql.tmpl`) is deliberately left out of it.

```
docker build -t formwork . && docker run --rm -p 8080:8080 -e FLAG='H7CTF{dummy}' formwork
```

## Solution

The flag is the workspace license key. `entrypoint.sh` writes it into `vault.license_key` and revokes `SELECT` on `vault` from the `app` role. No flag file, no table the app can read.

Field add/rename/drop and the blueprint import all quote identifiers with `pgx.Identifier{name}.Sanitize()`. That's a real quoted identifier, so hammering the field name into `ALTER TABLE` is a dead end.

The interesting part is sealing. It calls `compute_fingerprint(baseid)`, a `SECURITY DEFINER` PL/pgSQL function owned by `rollup_owner`, the only role that can read `vault`. You don't get its source, but its behaviour gives it away. It:

- creates a temp table `_stage(field, frag)`,
- seeds one row `(<anchor>, <license key>)`, where the anchor is a random per-instance token,
- for every field, runs a dynamic `EXECUTE` built by concatenating `col_ident` into a quoted literal:
  `'INSERT INTO _stage(field,frag) SELECT ''' || col_ident || ''', md5(frag) FROM _stage WHERE field=''<anchor>'''`
- writes `string_agg(DISTINCT field ...)` into the base's "components" note.

So `col_ident` goes raw into a string inside a definer context, and `EXECUTE` happily runs multiple statements.

Getting a payload into `col_ident` takes one more step. The field editor slugifies the label, so quotes and punctuation are stripped. The bulk import at `POST /api/bases/:id/import` trusts its own export format and stores `col_ident` verbatim.

The anchor is per instance, so we seal a throwaway base first and read the `anchor_...` token from the components note. Then import a blueprint with one field whose `col_ident` is:

```
', md5(frag) FROM _stage WHERE field='<anchor>'; INSERT INTO _stage(field,frag) SELECT frag, 'x' FROM _stage WHERE field='<anchor>'; --
```

That turns the dynamic SQL into three statements: the original insert (closed off cleanly), our insert that copies the license key into the `field` column, and a comment that eats the tail. Seal once, reload the base page, and the license key is listed as one of the components.

```
python3 solution/solve.py http://127.0.0.1:8080
```

Sealing is rate limited, only to stop spraying. Flag is dynamic, one per team.
