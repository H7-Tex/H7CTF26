# Interlock - writeup

A keygen crackme. The whole point is to recognise the key check for what it is - a linear system -
and solve it, rather than trying to reverse "an algorithm."

## 1. The check
`interlock` reads 16 bytes and runs a double loop:

```
for i in 0..15:
    acc = 0
    for j in 0..15:
        acc += A[i][j] * key[j]
    if (acc & 0xff) != B[i]: reject
```

`A` is a 16x16 byte matrix and `B` a 16-byte vector, both in `.rodata`. So the accept condition is
exactly a system of linear congruences:

```
A * key == B   (mod 256)
```

Brute force is 2^128 - but this is linear, so there's nothing to brute force.

## 2. Solve mod 256
`Z/256` is a ring, not a field: you can only divide by odd numbers (the units). `A` was built to be
invertible modulo 2, which means at every elimination step some remaining row has an **odd** entry in
the pivot column - use it as the pivot, multiply its row by `pow(pivot, -1, 256)`, and eliminate.
Gaussian elimination that only ever pivots on odd entries solves the system and gives the unique key:

```
UNLOCK-SEQ-7Y2AB
```

## 3. The token
On a valid key the binary computes `MD5(key)` and AES-128-CBC-decrypts (zero IV, PKCS7) the blob in
`.rodata`. Feed the key back, or decrypt offline. `solution/solve.py` does it all off the handout:
locate `A`/`B` in `.rodata` (the flag blob, `B`, and `A` sit contiguously), solve mod 256, MD5 + AES.

`H7CTF{l1n34r_syst3m_k3yg3n_m0d_256}`

## Build
`python3 challenge/gen.py` (emits `interlock_data.h`) then
`gcc challenge/interlock.c -o challenge/interlock -lcrypto -Os -s`. `interlock.zip` is the handout.

## Teaching / realism
Recognising algebraic structure in a check (linear, affine, XOR-linear) and solving it instead of
brute-forcing is a core reversing/keygen skill, and modular linear algebra over `Z/2^n` (odd-pivot
Gaussian elimination) shows up in real crackmes, DRM, and lightweight ciphers. It's a deliberately
different muscle from Warden (VM emulation) and Tollgate (Go-binary word transforms).
