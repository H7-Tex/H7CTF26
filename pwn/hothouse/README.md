# Hothouse

`pwn` / `insane` / on-demand per-team instance (tcp) / 1000 pts / dynamic flag

A firmware control link for a cellular-automaton coprocessor. Load a seed lattice, let it incubate for a few generations, and fire the settled fabric on the core. Coax the fabric into doing something it was never meant to, and read the flag off the box.

See `writeup/README.md` for the intended path and the reference solve.

## Files
- `challenge/` : build.sh, entrypoint.sh, hothouse.c
- `handout/` : RULE.md, hothouse.zip
- `solution/` : solve.py
