# Papers Please

**Category:** pwn  **Difficulty:** easy  **Author:** abu

> The Sparrow Freight border checkpoint takes down your name, denies you entry, and tells you to turn back. Somewhere behind the booth is the stamp that waves people straight through, and the guard is not going to reach for it on your account.
>
> So reach for it yourself.

Handout: `challenge/checkpoint.zip` (binary, libc, ld). Source is in `challenge/checkpoint.c`.

## Solution

Plain ret2win, the warm-up of the pwn set.

`checkpoint()` has `char name[64]` and does `read(0, name, 256)`. There is also a `grant_access()` that opens `/flag` and prints it, and nothing ever calls it. Built with `-fno-stack-protector -no-pie`, so no canary and fixed addresses. NX is on, but we don't need shellcode.

`name` sits at `rbp-0x40`, plus 8 for saved rbp, so the return address is at offset 72. `grant_access` is at `0x401216`.

Jumping straight to it crashes inside `printf` on a `movaps`, the usual alignment thing. One `ret` gadget first fixes the stack:

```python
payload = b"A" * 72 + p64(0x40101a) + p64(0x401216)   # ret ; grant_access
```

```
python3 solution/exploit.py <host> <port>
```

Flag is dynamic per team. Local one: `H7CTF{r3t2w1n_ch3ckp01nt_0v3rfl0w}`
