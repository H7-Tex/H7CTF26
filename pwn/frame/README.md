# Frame of Reference

**Category:** pwn  **Difficulty:** insane  **Author:** abu

> Attest is our streaming notary: hand it a keypair and it starts finalizing the key while you compose the document to sign, then hands back a recombined signature.
>
> Recover the secret only the internal auditor is supposed to read.

Handout: `handout/frame_of_reference.zip` (the exact `attest` binary served remotely, `attest.cpp`, build notes).

```
docker build -t frame_of_reference . && docker run --rm -p 1337:1337 -e FLAG='H7CTF{dummy}' frame_of_reference
```

## Solution

`attest` is a small C++20 menu:

1. `prepare` reads `e`, `p`, `q` in hex, allocates a `KeyMaterial` from a fixed slab and starts the coroutine `finalize(const KeyMaterial& km, Session&)`. It runs until the first `co_await` and suspends. Then `prepare` frees the `KeyMaterial` cell.
2. `submit` resumes the coroutine. It prints `n = p*q`, computes `d` and writes it back into `km.p` as scratch.
3. `cipher` allocates a post-processing object. `Notary` (and the hidden subclass `EscrowAudit`) come from the same slab.
4. `sign` calls `signer->run(msg)` through the vtable.

The bug is the `&`. A coroutine keeps a by-reference parameter as a raw pointer in its frame, not a copy. `prepare` frees the cell right after the coroutine suspends, so the frame holds a dangling pointer.

`KeyMaterial` has `p` first, so `p.limbs[0]` is at offset 0. `Notary` is polymorphic, vptr at offset 0, and its constructor only touches the first 56 bytes. So if we do `prepare` -> `cipher` (Notary) -> `submit`:

- `km.p` is now the Notary vptr.
- `km.q` (offset 56) still holds the small value we sent.

**Leak.** `submit` prints `n' = p' * q'`. We picked `q'`, so `p' = n' / q'` is the vptr. It looks like an RSA modulus and invites factoring or dlog, but it's just a division.

**Write.** The only store into the cell is `km.p = d`, with `d = inv(e', lcm(p'-1, q'-1))`. If `d` equals the `EscrowAudit` vptr, `sign` lands in `EscrowAudit::run`, which XORs `$FLAG` with our message. The two vtables are a fixed distance apart:

```
off = &_ZTV11EscrowAudit - &_ZTV6Notary     # nm on the handout binary
target = p' + off
```

Set `e' = inv(target, lambda')` and the server computes `d = target`, but only if `gcd(target, lambda') = 1` and `target < lambda'`. Two traps there:

- `target` is 8-byte aligned, so even. With an odd prime `q'`, `lambda'` is even and there is no inverse. Use an even `q'`.
- `q' = 2` gives `lambda' = p'-1 < target`, and the write becomes `target mod (p'-1)`, a tiny number. Use `q' = r + 1` with a large odd `r` (e.g. 1000003) so `lambda'` is well above `target`.

With `off = 48`, a layout only fails when `7 | (p'-1)`. Every connection is a fresh fork with fresh ASLR, so just reconnect.

Then `sign` with an all-zero message and the hex that comes back is the flag. The flag is only in the environment and only read by `EscrowAudit::run`, so there's no static shortcut.

```
HOST=<host> PORT=<port> BINARY=./attest python3 solution/solve.py
```

Flag is dynamic per team.
