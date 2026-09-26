# Keepalive

`pwn` / `insane` / on-demand per-team instance (tcp) / 500 pts / dynamic flag

gatecache is our edge authorization cache: it pins each session to its resolved principal so the hot path never has to look up who you are twice. Only an admin principal renders the artifact, and admin is a tier we never hand out. Render the artifact anyway.

See `writeup/README.md` for the intended path and the reference solve.

## Files
- `challenge/` : build.sh, gatecache.cpp
- `handout/` : keepalive.zip
- `solution/` : solve.py
