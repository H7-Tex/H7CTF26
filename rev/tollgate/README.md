# Toll Story

**Category:** Rev  **Difficulty:** Medium  **Author:** abu

> Toll Story is the admin lane of an internal API gateway. Show it the right token and the booth waves through the cluster bootstrap secret; show it anything else and you get "access denied."
>
> There's a toll on this road, and it isn't paid in cash.

One instance per team. The instance builds a fresh `tollgate` binary around that team's flag and serves it over HTTP (`challenge/serve.py`).

## Solution

`tollgate` is a stripped Go binary (`-ldflags="-s -w" -trimpath`). It asks for an `admin token:` and prints `access denied` for anything wrong. `strings` shows the success message but no flag, so it's encrypted somewhere.

No symbols, but the check is a small function that loads 16 bytes as four big-endian `uint32` words, does the same thing to each, and ANDs the results. In the decompiler you can see `bits.RotateLeft32`, `encoding/binary` loads and four sets of constants. Each word is checked as:

```
rotl32(w[i] ^ xorK[i], rot[i]) + addA[i] == target[i]
```

The constants are together in the data section, right before the ciphertext:

```
xorK   = 7c5afe6c 1ddf8cdb 9362ba25 a689a4ca
rot    = 22 12 3 20
addA   = b441f5cf 3fbcb9d9 10ceff09 7b7f535f
target = 824f1143 7bc67cb2 4a86f74e 5b3e302e
```

Every step inverts: `w[i] = rotr32(target[i] - addA[i], rot[i]) ^ xorK[i]`. Pack the words big-endian and you get `H7-T0LLG4TE-KEY1`.

With a valid token the binary does `sha256(token)` and AES-256-CBC decrypts (zero IV, PKCS7) a 48 byte blob. The solver doesn't even bother finding the blob; it slides a 48 byte window over the binary and keeps whatever decrypts to valid padding starting with `H7CTF{`.

```
python3 solution/solve.py ./tollgate
```

Flag: dynamic, `H7CTF{...}` per team. The local default build gives `H7CTF{g0_str1pp3d_t0llg4t3_w0rd_r3v}`.
