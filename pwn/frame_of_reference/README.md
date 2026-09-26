# Frame of Reference

`pwn` / `insane` / on-demand per-team instance (tcp) / 1000 pts / dynamic flag

Attest is our streaming notary: hand it a keypair and it starts finalizing the key while you compose the document to sign, then hands back a recombined signature. Recover the secret only the internal auditor is supposed to read.

See `writeup/README.md` for the intended path and the reference solve.

## Files
- `challenge/` : attest.cpp, build.sh, entrypoint.sh
- `handout/` : frame_of_reference.zip
- `solution/` : solve.py
