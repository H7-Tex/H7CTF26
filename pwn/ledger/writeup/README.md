# Ledger - writeup

The heap challenge: a use-after-free driven into tcache poisoning on modern glibc (2.39), with the
two things that trip people up on new glibc handled explicitly - **safe-linking** and the **tcache
alignment check**.

## The bug
`delete()` frees a note but leaves the pointer in the array; `view()` and `edit()` still operate on
freed notes. So we have a UAF read (leak) and a UAF write (poison). All notes are `malloc(0x50)` ->
0x60 chunks (one tcache bin). No PIE, Partial RELRO (GOT writable). There's an `audit()` that prints
`/flag`, never called.

## 1. Leak the heap (defeat safe-linking)
Since glibc 2.32, a freed tcache chunk's `fd` is *mangled*: `fd = (chunk_addr >> 12) XOR next`. Free a
single chunk (so `next == NULL`) and `view` it: `fd = chunk_addr >> 12` - the "heap key" you need to
mangle your own pointers.
```
add(0); add(1); delete(0); leak = view(0)[:8]   # = chunk0 >> 12
```

## 2. Poison a tcache fd
Free a second chunk (bin now has 2 - important, see below), then `edit` the freed head chunk's `fd` to
point at a GOT entry:
```
delete(1)                                  # bin: chunk1 -> chunk0
edit(1, p64(leak ^ malloc_got))            # mangle(malloc@got); chunk1 and chunk0 share a page,
                                           # so chunk1>>12 == leak
```
Target choice matters:
- glibc 2.39 aborts on an **unaligned** tcache chunk, so the target must be 16-byte aligned.
  `malloc@got` (0x404040) is.
- `tcache_get` zeroes the popped entry's `key` field (offset +8). `malloc@got+8` is `setvbuf@got`,
  which is only used once at startup - nulling it is harmless. (Targeting `free@got` would null
  `puts@got` and crash the menu - a good trap.)

## 3. Allocate over the GOT and win
```
add(2)                # pops chunk1 -> tcache head becomes malloc@got
add(3, p64(audit))    # pops malloc@got, returns it; write audit() there
add(5)                # any allocation now calls malloc@got == audit() -> prints /flag
```
`audit` starts with `endbr64`, so the indirect jump satisfies IBT (the binary is built with CET).

`H7CTF{us3_4ft3r_fr33_t04ch3_p01s0n_g0t}` (per-team dynamic on the live instance).
`solution/exploit.py` runs it end to end (run it from the directory containing the `ledger` binary).

## Deploy
Per-team on-demand docker; `entrypoint.sh` seals `$FLAG` into `/flag`, `socat` serves on tcp/9999.
Built in `ubuntu:24.04` (glibc 2.39). Validated end-to-end: the exploit leaks, poisons, overwrites
`malloc@got`, and reads the flag over TCP against the real container.

## Teaching
UAF, tcache internals, safe-linking pointer mangling, the tcache alignment check, and a GOT overwrite
under Partial RELRO + CET/IBT - the modern-glibc heap toolkit. The hard rung of the pwn slate below The
Ladder.
