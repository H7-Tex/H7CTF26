# Cipherlock - writeup

A constraint-solving crackme. Where Interlock's check was linear (solvable with modular linear
algebra), Cipherlock mixes in **non-linear** relations (byte products mod 256), which breaks Gaussian
elimination. The intended tool is an SMT solver.

## The check
Reverse `check()` and you find three families of constraints on the 16 key bytes, with the constants
(`CX`, `CY`, `CZ`) in `.rodata`:

```
XOR couplings :  k[i] ^ k[(i+3)%16]               == CX[i]        (16)
byte products :  (k[2i] * k[2i+1]) & 0xff         == CY[i]        (8, non-linear)
rotate + add  :  (rol8(k[i],3) + k[(i+5)%16])&0xff == CZ[i]        (16)
```

40 constraints over 16 bytes - heavily over-determined, so the key is unique.

## Solve with z3
Model each key byte as an 8-bit `BitVec` (so all arithmetic wraps mod 256 automatically) and add the
constraints verbatim; z3's rotate is `RotateLeft`. A printable-ASCII constraint on each byte helps and
matches the real key:

```python
b = [z3.BitVec(f"b{i}", 8) for i in range(16)]
s = z3.Solver()
for i in range(16): s.add(b[i] ^ b[(i+3)%16] == CX[i])
for i in range(8):  s.add(b[2*i] * b[2*i+1] == CY[i])
for i in range(16): s.add(z3.RotateLeft(b[i],3) + b[(i+5)%16] == CZ[i])
for i in range(16): s.add(b[i] >= 0x20, b[i] < 0x7f)
s.check(); key = bytes(m[b[i]].as_long() for i in range(16))
```
-> `S4T-C0NSTR4INT!7`.

## The flag
Valid key -> `MD5(key)` -> AES-128-CBC (zero IV, PKCS7) decrypt of the `.rodata` blob.
`H7CTF{z3_smt_s0lv3s_th3_c1ph3rl0ck}`. `solution/solve.py` does it end to end.

## Build
`python3 challenge/gen.py` (also asserts, via z3, that the key is the UNIQUE solution) then
`gcc challenge/cipherlock.c -o challenge/cipherlock -lcrypto -Os -s`. `cipherlock.zip` is the handout.

## Teaching / realism
SMT-based reversing is a core modern skill: when a check is a pile of arithmetic/bitwise constraints,
you model it and let z3 solve rather than inventing an inverse. Deliberately paired with Interlock -
that one rewards spotting linearity and solving it directly; this one is non-linear and pushes you to
z3. Warden (VM), Tollgate (Go), Interlock (linear algebra), Cipherlock (SMT) each drill a different
reversing muscle.
