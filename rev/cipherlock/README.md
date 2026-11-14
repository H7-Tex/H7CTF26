# Constraint Yourself

**Category:** Rev  **Difficulty:** Medium  **Author:** abu

> Cipherlock is the last lock in the vault, and it's a stubborn one: the key it wants has to satisfy it on every count or the door doesn't budge. Anything short of exactly right gets a flat "denied."
>
> Some locks you pick. This one you have to reason with.

One instance per team. The instance builds a fresh `cipherlock` binary around that team's flag and serves it over HTTP (`challenge/serve.py`).

## Solution

`cipherlock` reads a 16 byte key and runs `check()`. Reversing it gives three groups of constraints, with the constants `CX`, `CY`, `CZ` sitting in `.rodata`:

```
k[i] ^ k[(i+3)%16]                   == CX[i]   (16)
(k[2i] * k[2i+1]) & 0xff             == CY[i]   (8)
(rol8(k[i], 3) + k[(i+5)%16]) & 0xff == CZ[i]   (16)
```

That's 40 constraints over 16 bytes, so the key is unique. The byte products are not linear, so the Gaussian elimination trick from Lockstep doesn't work here. We just threw it at z3. 8 bit BitVecs wrap mod 256 for free, and a printable ASCII bound speeds it up:

```python
b = [z3.BitVec(f"b{i}", 8) for i in range(16)]
s = z3.Solver()
for i in range(16): s.add(b[i] ^ b[(i+3)%16] == CX[i])
for i in range(8):  s.add(b[2*i] * b[2*i+1] == CY[i])
for i in range(16): s.add(z3.RotateLeft(b[i], 3) + b[(i+5)%16] == CZ[i])
for i in range(16): s.add(b[i] >= 0x20, b[i] < 0x7f)
```

That gives `S4T-C0NSTR4INT!7`. On a valid key the binary takes `MD5(key)` and AES-128-CBC decrypts (zero IV, PKCS7) a blob in `.rodata`. Feed it the key or decrypt offline.

```
python3 solution/solve.py ./cipherlock
```

Flag: dynamic, `H7CTF{...}` per team. The local default build gives `H7CTF{z3_smt_s0lv3s_th3_c1ph3rl0ck}`.
