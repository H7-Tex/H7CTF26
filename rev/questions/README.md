# Twenty Questions

**Category:** Rev  **Difficulty:** Insane  **Author:** abu

> A hardware lab audits a sealer routine that swallows a device secret, stirs it, and shreds the leftovers. You do not get gdb. You get the Interrogator: it runs the bytecode you submit, and it counts every question you ask.
>
> Pull the secret back out, in as few questions as you can.

Handout: `handout/twenty-questions.zip` (`sealer`, the local `simulator`, `asm.py`, `ISA_SPEC.md`, `example.tqa`). One instance per team over TCP. This one is relative graded: any correct recovery gets the flag and banks 0.25, and the rest of the score is gas efficiency.

## Solution

`sealer` is a static no-PIE x86-64 ELF. It reads a 16 byte secret from `$FLAG`, gets a fresh 16 byte key from `getrandom`, and builds one writable page, the "device RAM" window:

```
0x000  ct[256]        16 real slots hold flag[pos] ^ prf(key, pos), the rest is random
0x100  sched[256]     which ct slot is processed in round r
0x200  pos[256]       flag position 0..15 for that slot, 0xFF for decoys
0x300  real_mask[256]
0x400  nrounds        256
0x404  digest[32]     lossy fold
```

The key lives on the stack, outside the window. For each round the loop computes `b = ct[sched[r]] ^ prf(key, pos[r])`, moves `b` into `dl` and the position into `cl` at one fixed address (the confession site), folds `b` into the digest and zeroes the slot. There's also a decoy `H7CTF{n0t_the_real_0ne_stepper}` in `.data`.

The Interrogator only lets you peek and poke inside the window, read registers at a stop, and set breakpoints/watchpoints, all under an 8000 gas budget. So `strings` finds the decoy, dumping the window only gets ciphertext, the digest can't be inverted, and the slot layout and key change every run. The plaintext only exists in a register at the confession site.

**Baseline, about 1800 gas.** Breakpoint the confession, `CONT` through all 256 rounds, `PEEKREG` rdx and rcx each time, keep bytes with position under 16, then `SUBMIT`. It reads positions live so it survives reseeding. That's `solution/baseline.tqa`.

**Optimal, 285 gas.** The important detail is that `prf` only depends on the key and the position, not on the round. And the sealer reads its schedule out of the window, which we can write. So we break before the loop (`pre_loop`, `0x40301a`), read `pos[]`/`sched[]` to find the 16 real slots for this run, and poke a new schedule: `nrounds = 16`, `sched[0..15]` = the real slots in order, `pos[0..15] = 0..15`. Now the confession (`0x403019`) fires exactly 16 times, in flag order, and we just read `dl` each time. `solution/optimal.py` writes `optimal.tqa`.

Score is `0.25 + 0.75 * clamp((ln 8000 - ln gas) / (ln 8000 - ln 285), 0, 1)`.

Against an instance:

```
python3 solution/solve.py <host> <port>
# {"solved": true, "gas": 285, "score": 1.0, "flag": "H7CTF{...}", ...}
```

Locally, with the same binary in live mode:

```
(cd challenge/interrogator && cargo build --release)
python3 challenge/interrogator/asm.py solution/optimal.tqa /tmp/optimal.bin
TQ_MODE=live FLAG='H7CTF{test_flag_1234567}' TQ_SEALER=challenge/sealer \
  TQ_WIN_BASE=0x4baac0 TQ_CONFESS=0x403019 TQ_BEST_KNOWN=285 \
  challenge/interrogator/target/release/interrogator < /tmp/optimal.bin
```

The deployed image and the handout both use the pinned `challenge/sealer`, so those addresses hold on every instance. If it's ever rebuilt, get the new addresses with `nm` and rerun `python3 solution/optimal.py <pre_loop> <confess> solution/optimal.tqa`, then update the env in the Dockerfiles and `graded/services.yaml`.

`challenge/Dockerfile` is the single container version (socat to the interrogator, needs `SYS_PTRACE`). `graded/services.yaml` is the graded setup: a public `portal` that only relays, and an internal `grader` that holds `$FLAG` and `GRADER_SECRET` and reports the score through `graded/grader/report.py`.

Flag: dynamic, `H7CTF{...}` per team.
