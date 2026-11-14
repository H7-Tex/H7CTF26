# Modem Operandi

**Category:** Rev  **Difficulty:** Medium  **Author:** abu

> Pulled from a grey-market satellite modem, this licence checker is all that stands between you and the carrier provisioning string. Every wrong key earns the same flat "rejected," and it is fussy about what it accepts.
>
> Every checker has a method; this one just won't say what it is.

Handout: `challenge/warden.zip`

## Solution

`warden` is a small stripped ELF. It asks for a `license key:` and prints `license rejected` for anything wrong. `strings` has the success message but no flag, so it's encrypted in `.rodata`. `main` reads 16 bytes, calls a validator, and on success derives an AES key and decrypts a blob.

The validator doesn't compare the input directly. It runs a tiny stack VM over a bytecode array in `.rodata`:

| op | meaning |
|----|---------|
| 01 i | push `license[i]` |
| 02 b | push `b` |
| 03 | xor |
| 04 | add (mod 256) |
| 05 n | rotate left by `n` |
| 06 b | pop, fail if `!= b` |
| 00 | halt |

The bytecode is 16 identical blocks, one per key byte, matching `01 . 02 . 03 02 . 04 05 . 06 .`. Each one boils down to:

```
rol8((license[i] ^ X[i]) + Y[i], R[i]) == T[i]
```

All of it inverts, so there's exactly one key: `license[i] = ((ror8(T[i], R[i]) - Y[i]) & 0xff) ^ X[i]`. Pulling the immediates out of each block gives `H7X-9F2A-COREKEY`.

On success it does `MD5(license)` and AES-128-CBC decrypts (zero IV, PKCS7) the 48 byte blob that sits right before the bytecode. Feed the key to the binary or decrypt offline:

```
python3 solution/solve.py challenge/warden
```

Flag: `H7CTF{476f0831f4c4eec5b790}`
