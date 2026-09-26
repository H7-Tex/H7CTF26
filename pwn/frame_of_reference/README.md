# Frame of Reference

`pwn` / `insane` / on-demand per-team instance (tcp) / 500 pts / dynamic flag

Attest is our streaming notary: hand it a keypair and it starts finalizing the key while you take your time composing the document to sign, then hands back a recombined signature. We overlap the slow key work with your network round trips so nobody waits.

See `writeup/README.md` for the intended path and the reference solve.

## Files
- `challenge/` : attest.cpp, build.sh, entrypoint.sh
- `handout/` : frame_of_reference.zip
- `solution/` : solve.py
