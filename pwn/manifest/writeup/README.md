# Manifest - writeup

A format-string write. The step up from Checkpoint: instead of smashing a return address, you use a
`printf` on attacker input to write to memory - overwriting a privilege flag.

## The bug
`feedback()` does `printf(buf)` on your input (no format string of its own). That's a classic
format-string vulnerability: your `%` specifiers are interpreted, letting you read (`%p`/`%s`) and
write (`%n`) via the stack.

## The target
`view_manifest()` gates the flag behind `if (!is_admin)`. `is_admin` is a global at a fixed address
(no PIE): `0x40407c`. Flip it to nonzero and option 2 prints the flag.

## Finding the offset
Send `BBBBBBBB.%p.%p.%p...`; the `0x4242424242424242` shows up at the **6th** format argument - so our
input begins at offset 6.

## The write
`%n` writes "characters printed so far" to the address in the pointed-to argument. Put the target
address in the buffer, keep the format part 8-byte aligned so the address sits at a clean argument
slot, and avoid leading null bytes (which would truncate the format string) by putting the format
specifiers first:

```
payload = b"%1c%7$n ".ljust(8) + p64(0x40407c)
```
- format part is 8 bytes -> the trailing `p64(is_admin)` lands at argument offset **7**.
- `%1c` prints 1 char (so the count is nonzero), then `%7$n` writes that count to `is_admin`.

Then send `2` -> `[manifest] clearance code: H7CTF{...}`. `solution/exploit.py` runs it (plain sockets).

`H7CTF{f0rm4t_str1ng_0v3rwr1t3_4dm1n}` (per-team dynamic on the live instance).

## Deploy
Per-team on-demand docker; `entrypoint.sh` seals `$FLAG` into `/flag`, `socat` serves the binary on
tcp/9999. Built in `ubuntu:24.04` (glibc 2.39) to match runtime. Validated end-to-end: the exploit
flips `is_admin` and reads the flag over TCP against the real container.

## Teaching
Format-string mechanics (arg offset discovery, `%n` write, 8-byte alignment, avoiding null bytes) and
overwriting a memory flag to bypass an authorization check - a different primitive from Checkpoint's
overflow, one rung harder.
