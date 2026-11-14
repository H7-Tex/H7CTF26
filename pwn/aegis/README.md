# The Ladder (Aegis Gateway)

**Category:** pwn  **Difficulty:** insane  **Author:** abu

> The same diagnostic console, shipped as five dated releases. Each release adds one more mitigation. Your score is the deepest rung you can clear (depth / 5), so climb.

Graded challenge (1000 base points). Handout: `graded/the-ladder.zip` (five `gateway_v*` binaries, libc 2.39-0ubuntu8.9, ld). Each rung runs in its own container and serves a per-instance token instead of a flag. You pop the rungs, collect the tokens and submit them on the portal, which relays them to an internal grader that scores depth. Deployment spec is `graded/services.yaml`; the binaries are built from `challenge/src/gateway.c` by `challenge/build_tiers.sh`.

| Release | Year | Adds |
|---|---|---|
| v1.0 | 2021 | NX, no canary, no PIE, Partial RELRO |
| v1.4 | 2022 | stack canary |
| v2.0 | 2023 | PIE |
| v2.6 | 2024 | Full RELRO, FORTIFY_SOURCE=2 |
| v3.0 | 2025 | seccomp (no execve/execveat) |

## Solution

Every release is the same source with different flags, and has the same two bugs:

- `IDENT <name>` does `printf(name)`.
- `DIAG <len>` does `read(0, buf, len)` into `char buf[64]`.

There is no win function on purpose. You need code execution or ORW on every rung.

**v1.0.** `IDENT %13$p` leaks a libc address. Overflow `DIAG` (return address at 88) with `pop rdi; /bin/sh; ret; system`, then `cat /flag`.

**v1.4.** Now there's a canary. `%9$p` is the canary and `%47$p` is the return into `__libc_start_call_main` (base + `0x2a1ca`). Put the canary back in place, same ret2libc.

**v2.0.** PIE on. Same two leaks still work, and the whole chain is libc gadgets anyway, so the binary base doesn't matter.

**v2.6.** Full RELRO kills the GOT and FORTIFY turns `printf` into `__printf_chk`, so `%n` and positional `%N$p` are gone. Plain sequential `%p|%p|...` still leaks. At `-O2` the frame changes: canary at `parts[45]`, libc return at `parts[53]`, 328 bytes of padding to the canary. The read in `DIAG` goes through an opaque pointer, so FORTIFY can't bound it and the overflow survives. The chain fires when `QUIT` makes `main` return.

**v3.0.** seccomp kills `execve`, so the chain does `open`/`read`/`write` on `flag` (relative, the service runs from `/`) instead. `rdx` is 0 when `main` returns and libc has no clean `pop rdx; ret` in range, so we used `pop rdx; leave; ret` (`0x9828d`): it sets `rdx = 64` and pivots to a second part of the chain we placed further down the payload.

All offsets are for the shipped glibc: `system 0x58750`, `/bin/sh 0x1cc42f`, `pop rdi 0x10c08d`, `ret 0x28a92`.

```
TARGET_HOST=<host> TARGET_PORT=<port> python3 solution/exploitv3.0.py
```

There's one script per rung (`exploitv1.py` ... `exploitv3.0.py`). `grader/harness.py` runs an exploit against a local build of a release several times with fresh flags, to check the exploits are reliable.

A sixth rung (v3.4, Intel CET) is in `build_tiers.sh` but was never deployed since it needs a CET-enforcing host.
