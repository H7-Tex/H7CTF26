# The Ledger Never Sleeps

`crypto` / `hard` / on-demand per-team instance (docker, HTTP oracle), dynamic flag.

A live ECDSA signing oracle (secp256k1) whose per-signature nonce comes from a
secret LCG `k_{i+1} = a*k_i + c (mod n)`. Nonces never repeat and carry no bit
bias (so repeated-`r` and HNP/lattice checks return nothing), but the LCG relation
between consecutive nonces leaks the key: each `k_i` is affine in the private key
`d`, and eliminating `a, c` across four nonces gives a quadratic in `d`. Recover
`d`, forge the `ADMIN_TRANSFER` the signer refuses to sign, and it releases the flag.

Real basis: LCG/related-nonce ECDSA key recovery (Trail of Bits, "ECDSA: handle
with care"; LadderLeak).

## Delivery
Per-team live instance. The container holds a fresh random key + LCG per team and
seals nothing statically: the flag (`$FLAG`, injected) is returned by `POST /forge`
only for a valid signature on the exact `ADMIN_TRANSFER` message. Player submits
that flag to Anvil. The oracle must be alive during the solve (it is interactive);
the flag itself survives instance reap for later submission.

## Endpoints
- `GET /pubkey` : signer public key.
- `POST /sign {msg}` : an ECDSA approval; refuses any `ADMIN_TRANSFER`.
- `POST /forge {msg,r,s}` : a valid `ADMIN_TRANSFER` signature returns the flag.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/app.py` : the signer service (secret key + LCG nonces; sign / forge).
- `challenge/Dockerfile` : the instance image (`h7ctf26/ledger-never-sleeps`).
- `solution/solve.py` : reference solver (collect sigs, recover `d`, forge, get flag).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' PORT=8080 python3 challenge/app.py &     # start the signer
python3 solution/solve.py http://127.0.0.1:8080            # -> recovers d, forges, prints the flag
```
Validated across 6 fresh random instances (6/6 recovered + forged). The container
is built and verified by the importer (Cloud Build), per repo convention.

## Fairness / anti-agent notes
- Per-team dynamic flag; the oracle is per-team with a fresh random key + LCG.
- Dead-end trap: the LCG never repeats a nonce, so repeated-`r` never occurs, and
  the top-bit-bias / HNP reflexes find nothing. The intended path is spotting the
  linear relation between nonces and eliminating the LCG coefficients.
- The key is cryptographically random (`secrets`); the LCG is the only weakness.
- ECDSA verify is standard; the difficulty is the crypto, not the harness.
