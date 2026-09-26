# Countersign

`rev` / `insane` / on-demand per-team instance (tcp) / 500 pts / dynamic flag

Countersign is the attestation core of a licensed firmware module. Slide a pass under the glass and the clerk stamps whatever you hand him, but the core itself only ever walks a route it can vouch for, and a route it cannot vouch for quietly becomes a different route that looks like it worked.

See `writeup/README.md` for the intended path and the reference solve.

## Files
- `challenge/` : build.sh, core.c
- `handout/` : countersign, countersign.zip, note.txt
- `solution/` : solve.py
