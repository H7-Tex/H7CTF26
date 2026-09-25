# Checkpoint - writeup

The pwn on-ramp: a textbook ret2win. It exists to teach the fundamentals - find the overflow, find
the target, control the saved return address - without canary/PIE/libc getting in the way.

## The bug
`checkpoint()` has `char name[64]` but does `read(0, name, 256)` - 256 bytes into a 64-byte buffer.
Straight stack overflow. `grant_access()` reads `/flag` and prints it, but nothing calls it.

## Mitigations
```
gcc ... -fno-stack-protector -no-pie -O0
```
No stack canary (overwrite the return address freely) and no PIE (addresses are fixed - no leak
needed). NX is on, but we don't need shellcode; we reuse `grant_access`.

## Offset
`name` is at `rbp-0x40` (64). Saved RBP is 8 bytes, so the saved return address is at offset
`64 + 8 = 72`.

## Payload
```
'A'*72 + p64(0x40101a) + p64(0x401216)
         \--ret gadget--/  \-grant_access-/
```
`grant_access` is `0x401216`. The single `ret` gadget (`0x40101a`) is chained first so the stack is
16-byte aligned when `grant_access` hits the SSE (`movaps`) inside its `fopen`/`printf` - the classic
ret2win alignment gotcha. `solution/exploit.py` sends it (plain sockets, no pwntools).

`H7CTF{r3t2w1n_ch3ckp01nt_0v3rfl0w}` (per-team dynamic on the live instance).

## Deploy
Per-team on-demand docker; `entrypoint.sh` seals the injected `$FLAG` into `/flag`, `socat` serves the
binary on tcp/9999 (one process per connection). Built in `ubuntu:24.04` (glibc 2.39) so the shipped
binary matches the runtime. Validated end-to-end: the exploit grants access + prints the flag over TCP
against the real container.

## Teaching
Overflow -> offset -> ret2win, plus the stack-alignment detail that trips up first-time pwners. The
on-ramp for the rest of the pwn slate (The Ladder, etc.).
