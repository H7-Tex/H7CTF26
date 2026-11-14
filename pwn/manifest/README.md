# Manifest Destiny

**Category:** pwn  **Difficulty:** medium  **Author:** abu

> Sparrow Freight keeps its cargo manifest under admin clearance, which is not something they planned on giving you. Good thing the terminal loves feedback and takes your every word to heart.
>
> Some of us are just destined for management.

Handout: `challenge/manifest.zip` (binary, libc, ld). Source is in `challenge/manifest.c`.

## Solution

`feedback()` does `printf(buf)` on our input. Format string bug.

Option 2, `view_manifest()`, only prints the flag `if (is_admin)`. `is_admin` is a global and the binary has no PIE, so it lives at a fixed `0x40407c`. We just need to write anything nonzero there.

Sending `BBBBBBBB.%p.%p.%p...` puts `0x4242424242424242` at the 6th argument, so the buffer starts at offset 6.

The address has null bytes, so it goes after the format part. We pad the format to 8 bytes so the address lands cleanly on offset 7:

```python
payload = b"%1c%7$n ".ljust(8) + p64(0x40407c)
```

`%1c` prints one char and `%7$n` writes that count (1) into `is_admin`. Then pick option 2 and it prints `[manifest] clearance code: H7CTF{...}`.

```
python3 solution/exploit.py <host> <port>
```

Flag is dynamic per team. Local one: `H7CTF{f0rm4t_str1ng_0v3rwr1t3_4dm1n}`
