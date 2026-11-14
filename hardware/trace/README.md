# Trace Amounts

**Category:** hardware  **Difficulty:** medium  **Author:** abu

> A contactless payment card keeps its key sealed in the chip and swears it never comes out. We watched it work a few thousand taps in a row.
>
> The key never left the card. Everything else did.

Per-team instance over HTTP. Each launch generates a fresh AES key and serves `traces.npy`, `plaintexts.npy` and `secret.enc`.

## Solution

We get a batch of power traces (one per encryption), the matching plaintexts, and the flag encrypted under the card's key. The key isn't in any file. This is plain correlation power analysis on unprotected AES.

The usual attack point is the round-1 S-box output, `SBOX[pt ^ k]`, and the card leaks roughly the Hamming weight of that byte. So for each of the 16 key bytes:

1. For every guess `k` in 0..255, build `HW(SBOX[pt[:, i] ^ k])` across all traces.
2. Pearson-correlate that vector against every time sample.
3. The right guess gives a sharp peak at the sample where that byte is processed. Wrong guesses stay in the noise.

Stick the 16 bytes together, decrypt `secret.enc` with AES-128-ECB, strip PKCS7, done. About 500 traces is enough and it runs in a few seconds.

```
python3 solution/solve.py <dir-with-the-three-files>
```

Local test without Docker:

```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/ta
python3 solution/solve.py /tmp/ta
```

Flag is dynamic, per team.
