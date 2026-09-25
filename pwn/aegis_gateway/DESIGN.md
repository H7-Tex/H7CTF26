# Aegis Gateway — "The Ladder" design spine

Relative-graded pwn flagship. One vulnerable service (Aegis Gateway diagnostic console),
shipped as six dated releases; each release adds one real-era mitigation. The player submits
ONE exploit; the grader runs it against each release; **score = the newest release it pops
reliably (>=8/10 runs)**. Framing: a vendor's hardening campaign 2021 -> 2026.

The design rule that makes a ladder actually bite: **each rung's mitigation must kill the
previous rung's cheapest technique**, forcing a new insight. The spine:

## The two bugs (same source, all releases)
- **IDENT `<name>`** -> `printf(name)` — an uncontrolled format string (write-capable via `%n`
  until FORTIFY lands).
- **DIAG `<len>`** -> `read(0, buf, len)` into `char buf[64]` — a stack overflow (canary lands
  at release 2).
- The flag is read only via **code execution** (shell or open/read/write on `./flag`). There
  is deliberately **no win() that prints the flag** — a win() would let every rung collapse to
  "leak + ret2win" and RELRO/seccomp/CET would never bite.

## The rungs

| Rel | Year | Mitigation added | Cheapest technique | What the new mitigation killed |
|-----|------|------------------|--------------------|--------------------------------|
| v1.0 | 2021 | NX (baseline), Partial RELRO, no PIE, no canary | fmt `%n` overwrite a GOT entry -> one_gadget/system (libc leak via `%p`) | — (on-ramp) |
| v1.4 | 2022 | + stack canary | same fmt `%n` GOT path, **but** any DIAG overflow now needs the canary; fmt still primary | naive overflow (must leak canary via `%p` if you overflow) |
| v2.0 | 2023 | + PIE | leak PIE base via `%p`, then fmt `%n` GOT / ret2libc | fixed binary addresses (must leak text base) |
| v2.6 | 2024 | + Full RELRO + FORTIFY_SOURCE=2 | GOT is read-only AND `%n` from a writable format aborts -> **pivot to FSOP**: DIAG overflow + libc leak -> forge `_IO_2_1_stdout_` (House of Apple 2) -> system | the entire fmt-`%n`-GOT technique |
| v3.0 | 2025 | + seccomp (execve/execveat blocked) | same FSOP/ROP but the target is **ORW** (open/read/write the flag), not a shell | execve -> `/bin/sh` |
| v3.4 | 2026 | + Intel CET (SHSTK+IBT) | ROP/ret2libc/SROP all die on the shadow stack -> **SFOP** (signal-oriented, ride `rt_sigreturn` through a fault) to chained ORW | every return-address-controlled chain (the whole ROP model) — **needs the CET box** |

## Notes
- Releases v1.0-v3.0 build + validate on normal Docker (glibc 2.39 / Ubuntu 24.04). v3.4 is
  the **only** CET-dependent rung -> deferred until the CET box lands; the challenge stands
  and scores without it (top rung just unreachable until then).
- glibc pinned to 2.39 (FILE/FSOP offsets are version-sensitive) — build + CI in one image;
  ship the exact `libc.so.6`+`ld` in the handout (the discipline contract).
- Each release is the SAME `gateway.c` compiled with a per-release flag set (`tiers/*.mk`),
  plus a seccomp wrapper at v3.0+ and the CET flag at v3.4.
- Grader: runs the submitted exploit against a fresh instance of each release, N times, fresh
  per-run flag; pass = the exploit exfiltrates that run's flag. Reliability >=8/10 = "cleared".
  score = newest_release_cleared / total. (Interface: relative-grading-judge.md section 7.)
