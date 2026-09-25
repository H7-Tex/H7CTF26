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
  score = newest_release_cleared / total. (Interface: relative-grading-engine-BUILD.md,
  which supersedes relative-grading-judge.md — INTERACTION-graded: each rung yields a per-tier
  token, a separate internal grader pod verifies tokens and reports the 0..1 depth score.)

## Build / validation status (2026-09-26)
Reference exploits validated end-to-end over TCP against fresh containers, pinned glibc
**2.39-0ubuntu8.9** (Dockerfile base digest sha256:008173c2…), each run exact-match on a
per-run flag. `max_tier` for the graded score = the count of shippable rungs below.

| Rel  | mitigations added                          | reference solve                        | status                    |
|------|--------------------------------------------|----------------------------------------|---------------------------|
| v1.0 | NX / Partial RELRO / no-PIE / no canary     | fmt %13$p libc leak → ret2libc          | ✅ validated (6/6)         |
| v1.4 | + canary                                    | %9$p canary + %47$p libc → ret2libc     | ✅ validated (6/6)         |
| v2.0 | + PIE                                        | %9$p + %47$p → ret2libc (libc-only ROP) | ✅ validated (6/6, 12/12)  |
| v2.6 | + Full RELRO + FORTIFY_SOURCE=2              | seq %p| leak (printf_chk) → ret2libc     | ✅ validated (6/6)         |
| v3.0 | + seccomp (execve/execveat killed)          | seq %p| leak → ORW ROP (open/read/write) | ✅ validated (6/6)         |
| v3.4 | + Intel CET (SHSTK+IBT)                      | SFOP (signal-oriented) → ORW            | ⏳ deferred — needs CET box |

Verified libc offsets for 2.39-0ubuntu8.9 (byte-checked against the shipped libc): system
0x58750, /bin/sh 0x1cc42f, `pop rdi;ret` 0x10c08d, `ret` 0x28a92; `%47$p`/`%53`(seq) libc
return sits at base+0x2a1ca.

**FORTIFY note:** v2.6/v3.0 were previously unsolvable — the `char * volatile p = buf` trick
did NOT stop gcc from emitting `__read_chk` at -O2, so DIAG aborted on len>64. Fixed in
`gateway.c` by handing the buffer to `read()` through a compiler-barrier'd opaque pointer
(`char *p = buf; __asm__ volatile("" : "+r"(p));`): `__builtin_object_size` is unknown at the
call site → plain `read` → overflow survives FORTIFY (printf's %n still blocked, GOT still RO).
