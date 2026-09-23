# DecryptoStat: intended solution

Launch the instance, then:
```
python3 solution/solve.py http://<instance>/
```
Recovers the v1 key in one query and the v2 key by averaging, submits each, and
prints both per-team flags. (`solution/solve.py` imports the shipped `challenge/ckks.py`.)

## Path (v1, flag 1)
1. `POST /v1/encrypt` a known vector -> you get an `id` and the ciphertext `(b, a)`.
2. `POST /v1/decrypt {id}` -> the decoded approximate plaintext (complex slots).
3. Re-encode that result: `encode(decode(b + a*s)) = b + a*s` exactly, because the
   canonical embedding is an exact inverse. So you now hold the ring element
   `b + a*s`. Subtract `b`: that is `a*s`.
4. `a*s = a*s` is a linear system in the 8 coefficients of `s` (the negacyclic
   multiplication matrix of `a` times `s`). Solve it mod `Q`. That is the secret key.
5. `POST /v1/recover {s}` -> flag 1.

## Path (v2, flag 2)
`/v2/decrypt` adds fresh zero-mean noise flooding each call, so step 3 returns
`b + a*s + smudge` and the recovered key is wrong by `a^{-1} * smudge` (a dense
random-looking poly) - a single query fails. But the flooding is zero-mean:
recover `b + a*s + smudge_k` for many queries `k` on the same ciphertext, average in
the signed domain, and the smudge cancels, leaving `b + a*s` exactly. Then solve as
in v1. About 400-600 queries suffices at these parameters. `POST /v2/recover {s}` -> flag 2.

The naive `/decrypt` only decrypts ciphertexts it issued, so you cannot short-cut by
submitting `(b=0, a=1)` to read `s` directly.
