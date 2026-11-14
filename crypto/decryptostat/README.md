# Loose Lips

**Category:** crypto  **Difficulty:** hard  **Author:** abu

> DecryptoStat crunches the numbers without ever peeking at your data, or so the pitch deck promises. The original service still hums along beside the hardened rewrite that was meant to make it behave.
>
> Both of them are hopeless at keeping a secret.

Players get `challenge/ckks.py` and a per-team HTTP instance on port 8080. Two flags: one for `v1`, one for `v2`.

## Solution

DecryptoStat is a toy CKKS service (N=8). Each version has `POST /vN/encrypt {values}` which returns an `id` and the ciphertext `(b, a)`, `POST /vN/decrypt {id}` which decrypts a ciphertext it issued, and `POST /vN/recover {s}` which takes the secret key and gives the flag.

CKKS is approximate. Decryption computes `b + a*s = m + e` and the service hands back the decoded value with the noise `e` still in it. That noise is the whole problem (Li-Micciancio, IND-CPA^D, EUROCRYPT 2021). `encode` is the exact inverse of `decode`, so re-encoding the returned slots gives us `b + a*s` exactly, mod Q.

For v1:

1. Encrypt any known vector, keep `(b, a)` and the `id`.
2. Decrypt it and run the result through `ckks.encode` to get `b + a*s`.
3. Subtract `b`. Now we have `a*s`, and `a` is public, so this is a linear system `M_a * s = a*s` where `M_a` is the negacyclic multiplication matrix of `a`.
4. Solve mod Q and submit `s` to `/v1/recover`.

One query. You can't shortcut it by sending `(0, 1)` to decrypt; `/decrypt` only works on ids the service issued.

v2 is the "hardened" version with noise flooding: every decrypt adds fresh zero-mean noise, so a single query gives you `s` plus garbage. But the noise is re-sampled each call and zero-mean. Decrypt the same ciphertext a few hundred times, re-encode each result, average in the signed domain, and the flooding cancels out back to `b + a*s`. About 400-600 queries was enough. Then solve exactly as in v1 and submit to `/v2/recover`.

```
python3 solution/solve.py http://<instance>/
```

Local:

```
FLAG_V1='H7CTF{a}' FLAG_V2='H7CTF{b}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080
```

Both flags are dynamic, per team.
