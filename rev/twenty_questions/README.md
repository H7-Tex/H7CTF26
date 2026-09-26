# Twenty Questions

`rev` / `insane` / on-demand per-team instance (tcp) / 500 pts / dynamic flag

A hardware lab audits a sealer routine that swallows a device secret, stirs it, and shreds the leftovers. You do not get gdb. You get the Interrogator: it runs the bytecode you submit, and it counts every question you ask. Pull the secret back out, in as few questions as you can.

See `writeup/README.md` for the intended path and the reference solve.

## Files
- `challenge/` : Dockerfile, build_handout.sh, entry.sh, interrogator, target
- `handout/` : ISA_SPEC.md, example.tqa, twenty-questions.zip
- `solution/` : baseline.tqa, gen_optimal.py, optimal.tqa
