# Dispatch - writeup

The third pwn rung: ret2libc. Same overflow primitive as Checkpoint, but there's no `win()` to jump
to, so you leak libc at runtime and call `system("/bin/sh")` yourself.

## The bug
`vuln()` has `char buf[64]` and `read(0, buf, 512)` - overflow. No canary, no PIE. Saved return
address is at offset `64 + 8 = 72`.

## Why a leak is needed
There's no function that reads the flag - you need a shell, which means calling `system` in libc, whose
address is randomized (ASLR). So: leak a libc address, compute the base, then call `system`.

Note glibc 2.39 removed `__libc_csu_init`, so the usual `pop rdi; ret` from CSU is gone - but the
binary ships one (`pop_rdi_ret`, `0x401176`).

## Stage 1 - leak libc
ROP `puts(puts@got)` to print the runtime address of `puts`, then return to `vuln` for a second go:
```
'A'*72 + p64(pop_rdi_ret) + p64(puts@got) + p64(puts@plt) + p64(vuln)
```
`libc_base = leaked_puts - libc.sym['puts']` (using the provided `libc.so.6`, Ubuntu glibc 2.39).

## Stage 2 - ret2libc shell
```
'A'*72 + p64(ret) + p64(pop_rdi_ret) + p64(binsh) + p64(system)
```
The leading `ret` keeps the stack 16-byte aligned for `system`'s SSE. `binsh` is
`next(libc.search(b'/bin/sh\0'))`. Then `cat /flag`.

`H7CTF{r3t2l1bc_l34k_th3n_sh3ll_d1sp4tch}` (per-team dynamic on the live instance).
`solution/exploit.py` runs the whole thing (pwntools).

## Deploy
Per-team on-demand docker; `entrypoint.sh` seals `$FLAG` into `/flag`, `socat` serves on tcp/9999.
Built in `ubuntu:24.04` (glibc 2.39); the exact `libc.so.6` is shipped in the handout so offsets match.
Validated end-to-end: the exploit leaks libc, pops a shell, and reads the flag over TCP against the
real container.

## Teaching
GOT/PLT leak, computing libc base, ROP with a provided libc, `system("/bin/sh")`, stack alignment for
libc calls, and the modern-glibc "no CSU gadget" wrinkle. The bridge between the basics (Checkpoint /
Manifest) and the flagship (The Ladder).
