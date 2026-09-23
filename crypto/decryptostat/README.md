# DecryptoStat

`crypto` / `hard` / on-demand per-team instance (docker, HTTP), two dynamic flags.

A CKKS approximate-homomorphic-encryption analytics service. CKKS decryption
returns an approximate plaintext that still contains the noise, and that noise
leaks the secret key (Li-Micciancio, the IND-CPA^D attack): from one issued
ciphertext `(b, a)` and the decoded decryption you recover `b + a*s` exactly (the
encoding is an exact inverse of the decoding), so `a*s = (b+a*s) - b` is a linear
system for `s`. `v1` returns the raw approximate decryption (single-query
recovery). `v2` adds fresh noise flooding per query, which defeats a single query;
averaging many queries cancels the zero-mean flooding and recovers the key anyway
(the documented flaw in that countermeasure).

Real basis: Li & Micciancio, "On the Security of Homomorphic Encryption on
Approximate Numbers" (EUROCRYPT 2021); the noise-flooding countermeasure and its
averaging bypass.

## Delivery
Per-team live instance with two independent keys (v1 naive, v2 hardened) and two
dynamic sub-flags (`FLAG_V1`, `FLAG_V2`, injected). Submit each recovered key to
`/vN/recover` to claim its flag; the sub-flags score independently (partial credit).

## Endpoints (per version v1/v2)
- `POST /vN/encrypt {values}` : encrypt a length-4 vector; returns `id` + ciphertext `(b, a)`.
- `POST /vN/decrypt {id}` : approximate decryption of an issued ciphertext (decoded slots). v2 adds noise flooding.
- `POST /vN/recover {s}` : submit the recovered ternary secret key to get the flag.

## Files
- `challenge.yml` : definition (two dynamic flags, on-demand docker, http:8080).
- `challenge/ckks.py` : the CKKS scheme (encode/decode, params, encrypt/decrypt). Shipped to players.
- `challenge/app.py` : the analytics service (v1 naive, v2 noise-flooded).
- `challenge/Dockerfile` : the instance image (`h7ctf26/decryptostat`); numpy.
- `solution/solve.py` : reference solver (v1 single query, v2 averaging).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG_V1='H7CTF{a}' FLAG_V2='H7CTF{b}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080     # -> recovers both keys, prints both flags
```
De-risked and validated: encode/decode round-trip 50/50; v1 single-query recovery
30/30; the smudge correctly defeats a single query 20/20; v2 averaging (about 400
queries) recovers the key 10/10; full service path 2/2 across instances. N=8 keeps
ciphertexts tiny (2 x 8 coefficients), so memory is not a concern.

## Fairness / anti-agent notes
- Two per-team dynamic flags; per-team random keys.
- The scheme (`ckks.py`) is shipped: the difficulty is realizing approximate
  decryption leaks the key and building the linear recovery, not reversing a harness.
- No trivial shortcut: `/decrypt` only decrypts ciphertexts the service issued
  (by id), so you cannot submit a crafted `(0, 1)` to read `s` directly.
- v2 is the anti-agent core: a single query provably fails, and the averaging
  attack costs many queries, which the Ledger economy meters.
