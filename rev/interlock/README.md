# Lockstep

**Category:** Rev  **Difficulty:** Medium  **Author:** abu

> Lockstep is the key controller off a depot door: one exact sequence opens it, and everything else leaves you out in the yard. It is not the guessing kind of lock.
>
> These tumblers were never going to fall one at a time.

One instance per team. The instance builds a fresh `interlock` binary around that team's flag and serves it over HTTP (`challenge/serve.py`).

## Solution

The binary reads 16 bytes and runs a double loop over them:

```
for i in 0..15:
    acc = sum(A[i][j] * key[j] for j in 0..15)
    if (acc & 0xff) != B[i]: reject
```

`A` is a 16x16 byte matrix and `B` a 16 byte vector, both in `.rodata`. So the check is just `A * key == B (mod 256)`. No point brute forcing 2^128 when it's linear.

The catch is that Z/256 is a ring, not a field, so you can only divide by odd numbers. `A` is invertible mod 2, which means at every step of elimination some remaining row has an odd entry in the pivot column. Pivot on that, multiply the row by `pow(pivot, -1, 256)`, eliminate, repeat. You get one key:

```
UNLOCK-SEQ-7Y2AB
```

On a valid key the binary does `MD5(key)` and AES-128-CBC decrypts (zero IV, PKCS7) the flag blob. The blob, `B` and `A` sit next to each other in `.rodata`, so the solver pulls them straight out of the binary:

```
python3 solution/solve.py ./interlock
```

Flag: dynamic, `H7CTF{...}` per team. The local default build gives `H7CTF{l1n34r_syst3m_k3yg3n_m0d_256}`.
