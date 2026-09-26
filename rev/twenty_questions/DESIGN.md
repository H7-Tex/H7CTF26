# Twenty Questions - design spine

Relative-graded rev/pwn flagship. Seeded by Nautilus DEF CON 2023 "evm" (author bytecode for a
tracer VM that drives a child under a gas budget) and 2024 "codewords" (gas-capped submitted
predicates). Original core: a real breakpoint/watchpoint/register-peek/memory-poke ptrace ISA,
and a combination-bug seam between the debugger's whitelisted POKE and a firmware routine's own
seed-permuted schedule. Flag = participation; leaderboard rank = gas efficiency (insight per
debug event).

## One-paragraph pitch
A hardware-security lab ships a "sealer" routine that ingests a device secret, diffuses it, and
shreds the plaintext so nothing sensitive survives at rest. Analysts cannot attach gdb: they
audit it through a locked-down forensic debugger ("the Interrogator") that runs *submitted
bytecode* - breakpoints, register peeks, windowed memory pokes - under a strict question budget,
because on the real device every debug event costs power and time. The audit question: can you
pull the secret out of a routine that never keeps it whole, in as few debug events as possible.
The leaderboard IS the audit metric.

## Why the flag cannot be shortcut (the anti-agent spine)
Four independent walls, so `strings`/decompile/dump/invert all fail and only live ISA interaction wins:

1. **No plaintext at rest.** The 16 flag bytes are stored in the device-RAM window only as
   `ct[slot] = flag[pos] XOR PRF(seed_key, pos)`. `seed_key` (16B, `getrandom` per run) lives on
   the sealer's stack, OUTSIDE the debugger's peek window. Plaintext materializes only transiently,
   in one register, at a single static "confession" instruction, then the source slot is zeroed.
2. **Peek is windowed (realistic forensic-debugger sandbox).** `PEEKMEM`/`POKEMEM` address the
   "device RAM" window only (offsets into the mmap'd control page). They cannot read the stack
   (`seed_key`) or code. So `ct[]` is readable but useless without the key; the key is unreadable.
   `PEEKREG` reads the child's GP registers (that is how you catch the confession byte). Code
   addresses for `BP` come from static RE of the shipped ELF (no-PIE, fixed vaddrs).
3. **Lossy digest.** After transit each byte folds into a 32-byte persistent digest that is a
   non-injective fold, so the end state cannot be inverted to the input. End-state inversion dies.
4. **Per-run reseed forces adaptive bytecode.** `seed_key`, the slot permutation, and the round
   schedule are fresh `getrandom` each run. Bytecode that hardcodes slot indices from one observed
   trace faceplants on the graded reseeded run: the program must branch on live-read positions.

Plus a **static honeypot**: a contiguous `H7CTF{n0t_the_real_0ne_stepper}` in `.data`. A naive
memory scanner finds it first and SUBMITs it - a wrong, non-per-team flag that burns a metered
attempt. It is identical across instances, so a human notices and re-plans; a dumper loops on it.

## The target: `sealer` (static, no-PIE, x86-64 ELF, ~8-12KB)
Reads 16-byte flag core from `$FLAG` (`H7CTF{<16 core>}`), `getrandom(seed_key,16)`. Builds one
writable mmap page = the **device-RAM window** (the only region the debugger may peek/poke):

```
offset  field           size   meaning
0x000   ct[256]         256    working buffer: 16 real slots hold flag[pos]^PRF(seed_key,pos);
                                240 decoy slots hold random bytes.
0x100   sched[256]      256    sched[r] = which ct[] slot is processed at round r.
0x200   pos[256]        256    pos[r]   = logical flag position 0..15 of that slot, else 0xFF (decoy).
0x300   real_mask[256]  256    real_mask[r] = 1 iff pos[r] < 16 (this round emits a real flag byte).
0x400   nrounds (u32)   4      = 256 initially. rounds actually executed.
0x404   digest[32]      32     lossy persistent fold (decoy sink; does NOT gate emitted plaintext).
```
`seed_key[16]` is a stack local, never in the window. The 16 real slots and their round order are
a per-run random permutation of 0..255.

Loop (single static confession site at a fixed vaddr `CONFESS`):
```c
for (uint32_t r = 0; r < win->nrounds; r++) {
    uint8_t s = win->sched[r];
    uint8_t p = win->pos[r];
    uint8_t b = win->ct[s] ^ prf(seed_key, p);   // b = plaintext flag[p] for real; garbage for decoy
CONFESS:                                          // mov dl, b ; mov cl, p   (single static instruction pair)
    __asm__ volatile("mov %0, %%dl; mov %1, %%cl" :: "r"(b), "r"(p) : "dl","cl");
    fold(win->digest, b, p);                      // lossy
    win->ct[s] = 0;                               // shred
}
pause();
```
`prf(k,p)` depends ONLY on `(seed_key, logical position p)`, NOT on round index or history -> so
collapsing/reordering the schedule keeps every real byte's plaintext correct (this is what makes the
poke-optimal valid). For decoys `p==0xFF`, `prf` returns junk and the byte is meaningless.

## The debugger ISA (the "Interrogator")
16 opcodes. 8 u64 regs `r0..r7`, 512B scratch. Bytecode <= 4KB, length-prefixed.

| op | form | gas | effect |
|----|------|-----|--------|
| IMM   | `IMM rD, imm64`         | 1   | rD = imm |
| MOV   | `MOV rD, rS`            | 1   | rD = rS |
| ALU   | `ALU op rD, rS`         | 1   | rD op= rS  (ADD/SUB/XOR/AND/OR/SHL/SHR/CMP-sets-flags) |
| BP    | `BP slot, addr`         | 10  | arm breakpoint #slot at code addr (INT3) |
| WP    | `WP slot, off, len`     | 20  | arm hardware watchpoint #slot on window[off..off+len] (len in {1,2,4,8}) |
| CONT  | `CONT`                  | 5   | continue child until next BP/WP hit or exit; sets flags = which slot hit |
| STEP  | `STEP`                  | 50  | single-step one instruction (the trap: never needed) |
| PEEKREG | `PEEKREG rD, regid`   | 1   | rD = child GP register regid (rax..r15, rip) at the current stop |
| PEEKMEM | `PEEKMEM rD, off`     | 2   | rD = 8 bytes of the window at byte offset `off` (window-only; else abort) |
| POKEMEM | `POKEMEM off, rS`     | 4   | write 8 bytes rS -> window[off] (window-only; out-of-window = 100 gas + abort) |
| JMP   | `JMP tgt`               | 1   | pc = tgt |
| JZ/JNZ/JLT | `Jcc tgt`          | 1   | conditional on ALU/CONT flags |
| SUBMIT | `SUBMIT off, len`      | 1   | recovered bytes = window[off..off+len]; verify vs live flag core |
| HALT  | `HALT`                  | 0   | stop the program |

Budget **8000 gas**, program <= 4KB. Out-of-window POKE = 100 gas + abort. On a correct SUBMIT the
grader emits the real `H7CTF{...}` and computes the 0..1 score from gas.

`getrandom` reseed each run + windowed peek + no-plaintext-at-rest are what force the ISA path.

## Intended solves + the gas gradient (relative score)
- **Baseline (adaptive, banks 0.25).** `BP 0, CONFESS; loop { CONT; PEEKREG r0,rdx (byte); PEEKREG
  r1,rcx (pos); if r1<16 store byte into scratch[r1] }` for all 256 rounds, then `SUBMIT scratch,16`.
  Reads positions live -> survives reseed. Cost ~ `10 + 256*(5+1+1) + 1 ~= 1800` gas. Correct but wasteful.
- **Optimal (the combination-bug, ~top of leaderboard).** Realize the debugger can rewrite the
  routine's OWN schedule. Set `BP` before the loop; `PEEKMEM` the `pos[]`/`sched[]`/`real_mask[]`
  tables to learn this run's 16 real (round,slot,position) live; `POKEMEM` a compact schedule:
  `nrounds=16`, `sched[0..15]` = the 16 real slots ordered by position, `pos[0..15]=0..15`, decoys
  disabled. Then `BP CONFESS`; `16 * (CONT + PEEKREG byte)`; `SUBMIT`. Cost ~ `10 (BP) + ~48 (read 3
  tables, 24 PEEKMEM*2) + ~8 (POKEs) + 16*(5+1) + 1 ~= 160-350` gas. Plaintext read straight from the
  register in flag order. **This is the insight the leaderboard pays for.**
- Because `prf` keys on position (not history), the collapsed schedule still emits correct plaintext.

## Scoring (fits relative-grading-engine-BUILD.md)
`score = 0.25 + 0.75 * clamp( (log(BUDGET) - log(gas_used)) / (log(BUDGET) - log(best_known)), 0, 1 )`
- Any correct SUBMIT banks 0.25 (participation), matching the LNS house rule (0.25 + 0.75*efficiency).
- `best_known` = the true optimum gas from the internal solver sweep (fix D), not a guess.
- `BUDGET = 8000`. Monotonic best per (team, challenge), engine-side.

## Security topology (matches §3 of the grading contract)
The Interrogator is a constrained VM (safe Rust; player drives the ISA, no code-exec), but we still
use the reviewed **portal + internal-grader** split so `GRADER_SECRET` never sits in a player-reachable
surface:
- **portal** (public, no secret): accepts length-prefixed bytecode, relays to grader, streams JSON back.
- **grader** (internal, egress + secret): runs the deterministic Interrogator over the submitted
  program against the live target ($FLAG + fresh `getrandom`), computes authoritative gas, verifies
  SUBMIT == live flag core, emits the flag to the player on success, computes the 0..1 score, and
  reports to Anvil `/evaluate` -> `/report` (reuse aegis_gateway `graded/grader/report.py` verbatim,
  SLUG = `twenty-questions`). Signing/headers per §4 (X-Anvil-Instance, team from ANVIL_TEAM_ID).
- **Economy (§5):** the metered unit is a fresh scored EPISODE (a reseeded live run). 3 free, then
  0.2 x 400 = 80 credits, 1 in-flight + 10-min cooldown. Iterating bytecode offline vs the shipped
  local simulator is free; a fresh graded run against the live flag is the priced decision.

## Fix C (parity, mandatory): ONE binary is both sim and scorer
The shipped local simulator and the remote grader are the SAME Rust binary, switched by env:
`TQ_MODE=sim` (placeholder flag `H7CTF{simsimsimsimx}`, fixed seed `TQ_SEED`) vs `TQ_MODE=live`
(reads `$FLAG`, `getrandom` seed). Identical gas + ptrace-stop semantics by construction, so a
program tuned offline scores identically online.

## Hosting
Plain docker-service, standard pool. socat -> portal (raw TCP via SNI on shared :1337). grader forks +
ptraces its own child; `--cap-add=SYS_PTRACE` + a seccomp profile allowing ptrace; no privileged/sysbox
pool, no GPU. Handout (target ELF + ISA spec + local simulator + Python assembler + 2 worked example
programs) from the public GCS bucket. Per-team $FLAG injected into the grader/target env at solve time.

## Build + validation checklist
- [ ] `sealer.c` builds static no-PIE; `CONFESS` at a fixed vaddr; window layout as above; honeypot present.
- [ ] Interrogator: full ISA, exact gas table, ptrace BP re-arm + CONT + windowed peek/poke, SUBMIT verify.
- [ ] `TQ_MODE` sim/live parity: same binary, same gas for the same program.
- [ ] Reference solvers: baseline (~1800) + optimal (set best_known); both correct across 10 reseeds.
- [ ] Python assembler + 2 worked examples in the handout.
- [ ] Solver sweep (fix D): prove no path beats best_known and no read-only/WP/digest shortcut exists.
- [ ] graded/ portal + grader (reuse report.py) + services.yaml topology; challenge.yml scoring: graded.
- [ ] em-dash-free player-facing text; description names no technique.
