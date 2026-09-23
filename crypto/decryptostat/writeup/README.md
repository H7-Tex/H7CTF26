# DecryptoStat: writeup

## The setup
DecryptoStat does analytics over CKKS approximate homomorphic encryption. You can
have it encrypt a vector (it returns the ciphertext `(b, a)` and an id) and decrypt
a ciphertext it issued (it returns the decoded result). CKKS is *approximate*: a
fresh encryption is `b = -a*s + m + e`, `a` random, and decryption computes

    b + a*s = m + e

then decodes to `m` (approximately). The service returns that approximate result.

## The bug (IND-CPA^D)
The returned plaintext is not the ideal `m`, it is `m + e/DELTA` at full precision.
That extra noise `e` is exactly what an exact scheme (BFV/BGV) rounds away, and it
leaks the key. Concretely, the canonical-embedding encode is the exact inverse of
decode, so from the returned decoded slots you can reconstruct the ring element
`b + a*s` exactly:

    encode(decode(b + a*s)) = b + a*s        (mod Q)

Subtract the known `b` and you have `a*s`. Since `a` is public (it is half the
ciphertext) and multiplication in `Z_Q[x]/(x^N+1)` is linear, `a*s` gives `N`
linear equations in the `N` coefficients of `s`:

    M_a * s = (b + a*s) - b       (M_a = negacyclic multiplication matrix of a)

Solve mod `Q` -> the secret key. One query. This is Li & Micciancio's IND-CPA^D
attack (EUROCRYPT 2021): approximate-HE decryptions must be treated as leaking the
secret key.

There is no trivial shortcut: `/decrypt` only decrypts ciphertexts the service
issued (tracked by id), so you cannot submit a crafted `(b=0, a=1)` to read `s`.

## v2: noise flooding, and why averaging beats it
The documented countermeasure is *noise flooding*: add large extra noise before
returning the decryption, to statistically hide `e`. `v2` does this with fresh
zero-mean noise per query. Now one query returns `b + a*s + smudge`, and solving
gives `s + a^{-1}*smudge`, a dense wrong key: a single query fails.

But the flooding is zero-mean and re-sampled each call. Recover `b + a*s + smudge_k`
for many queries on the *same* ciphertext, average them in the signed domain, and
the smudge averages to zero, leaving `b + a*s` exactly. Solve as before. About
400-600 queries suffices here. Averaging out unbiased flooding is precisely the
known flaw in that countermeasure; a correct fix must use a differentially-private
mechanism, not simple re-sampled flooding.

## Steps
1. v1: encrypt a known vector, decrypt it, `encode()` the result to get `b + a*s`,
   subtract `b`, solve `M_a s = a*s` mod Q -> key -> `/v1/recover` -> flag 1.
2. v2: same, but average many `/v2/decrypt` results (signed domain) to cancel the
   flooding, then solve -> key -> `/v2/recover` -> flag 2.

## Notes
- The scheme (`ckks.py`) is shipped; the challenge is the attack, not reversing it.
- Real basis: Li & Micciancio, EUROCRYPT 2021; OpenFHE's `NOISE_FLOODING_DECRYPT`
  and the averaging bypass of naive flooding.
