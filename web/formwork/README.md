# Formwork

`web` / `hard` / on-demand per-team instance (http) / 500 pts / dynamic flag

Formwork is our internal low-code base builder. Spin up a base, shape its fields, and seal it so the schema gets signed and any later drift shows up. Read the record no base is supposed to contain. The workspace license key does the signing. The name is your only hint about what a mold is really for.

See `writeup/README.md` for the intended path and the reference solve.

## Files
- `challenge/` : deploy, entrypoint.sh, go.mod, go.sum, main.go, templates.go
- `handout/` : README.md, formwork.zip
- `solution/` : solve.py
