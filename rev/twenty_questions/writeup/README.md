# Twenty Questions - writeup

Relative-graded. The flag is participation; the leaderboard rank is gas efficiency (debug events).

## Target
`sealer` is a static no-PIE x86-64 ELF. It reads a 16-byte secret core from `$FLAG`, draws a fresh
16-byte key with `getrandom`, and builds a single writable page (the "device RAM" window):

- `ct[256]`   : working buffer. The 16 real slots hold `flag[pos] ^ prf(key, pos)`; the other 240 are random.
- `sched[256]`: `sched[r]` = which `ct` slot is processed at round `r`.
- `pos[256]`  : `pos[r]` = logical position 0..15 of that slot, or 0xFF for a decoy.
- `real_mask`, `nrounds` (=256), `digest[32]` (a lossy fold).

The key lives on the stack, outside the window. The diffusion loop, for `r < nrounds`, computes
`b = ct[sched[r]] ^ prf(key, pos[r])` (the plaintext byte for a real slot), calls `confess(b, pos)`
at a single static site, folds into the lossy digest, and zeroes the source slot. A static honeypot
`H7CTF{n0t_the_real_0ne_stepper}` sits in `.data`.

`prf` depends only on `(key, position)`, never on round history: this is why rewriting the schedule
still yields correct plaintext.

## Why the obvious things fail
- `strings`/decompile: only the honeypot is contiguous; the real flag never exists in the binary.
- Dump the window: `ct` is ciphertext and the key is off-window (the debugger's peek is windowed), so
  there is no at-rest plaintext to read and no key to decrypt it with.
- Invert the end state: the digest is a lossy fold.
- Record one trace and replay fixed slot indices: the permutation and key reseed every run.
- Single-step to scan memory: STEP costs 50 gas and the flag is never contiguous; a scanner finds the
  honeypot and burns an attempt.

So the plaintext can only be observed transiently, in a register, at the confession, on a live run.

## Baseline (banks 0.25, ~1800 gas)
Breakpoint the confession site, `CONT` through all 256 rounds, `PEEKREG` the byte and position at each
hit, keep the ones with position < 16, place by position, then `SUBMIT`. Adaptive (reads positions
live) so it survives the reseed. See `solution/baseline.tqa`.

## Optimal (the insight, ~285 gas, score 1.0)
The debugger can write the device RAM window, and the sealer reads its schedule from that window each
round. So: breakpoint `pre_loop` (before any round runs), read `pos[]`/`sched[]` to learn which slot
holds each of the 16 positions this run, then POKE a compact schedule (`nrounds = 16`,
`sched[0..15]` = the real slots in position order, `pos[0..15] = 0..15`). Now the confession fires 16
times, in order, emitting the flag. `solution/gen_optimal.py` emits this program; it scans the tables
in a 32-word loop (cheap) and reads plaintext straight from the register.

Baseline 1800 -> optimal 285 is the efficiency gradient the rank rewards.

## Scoring
`score = 0.25 + 0.75 * clamp((ln(BUDGET) - ln(gas)) / (ln(BUDGET) - ln(best_known)), 0, 1)`,
`BUDGET = 8000`, `best_known = 285`. Monotonic best per team, engine side.

## Deploy
Single-pod quick form: `challenge/Dockerfile` runs `socat -> interrogator` (needs `SYS_PTRACE`).
Relative-graded form: `graded/services.yaml` splits a public `portal` (relay, no secret) from an
internal `grader` (holds `$FLAG` + `GRADER_SECRET`, runs the interrogator, reports the 0..1 to Anvil
via `graded/grader/report.py`, per the graded report contract). `TQ_BEST_KNOWN=285`.
