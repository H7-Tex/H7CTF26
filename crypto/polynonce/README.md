# Polynonce

`crypto` / `hard` / on-demand per-team instance (docker), dynamic flag.

ECDSA over secp256k1 where the per-signature nonce is not random: it follows a
hidden degree-2 polynomial recurrence `k_{i+1} = c2*k_i^2 + c1*k_i + c0 (mod n)`.
Nonces never repeat and carry no top-bit bias, so repeated-`r`, HNP/lattice, and
bias checks all return nothing. The recovery is pure synthesis on the
cross-signature structure: each `k_i` is affine in the private key `d`, the
recurrence turns that into a polynomial in `d`, and its root mod `n` is the key.

Real basis: the Polynonce attack (Kudelski Security, DEF CON 31, 2023).

## Delivery
Per-team instance. On launch, the container generates a fresh random key +
signatures and seals the platform-injected `$FLAG` into `flag.enc`, then serves
`signatures.json` + `flag.enc` over HTTP. The player downloads both, solves
offline, recovers `d`, decrypts, and submits their per-instance `H7CTF{...}`.
A leaked flag is worthless (per-team) and a leaked handout is per-team.

## Files
- `challenge.yml` : challenge definition (dynamic flag, on-demand docker).
- `challenge/gen.py` : per-instance handout generator (fresh cryptographically
  random key each launch; seals `$FLAG`). Runnable standalone for local testing.
- `challenge/serve.py` : instance entrypoint (generate + serve handout on :8080).
- `challenge/Dockerfile` : the instance image (`h7ctf26/polynonce`).
- `solution/solve.py` : reference solver (pure Python, no Sage). Recovers `d`, decrypts.
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
# generate one instance's handout with a test flag, then solve it
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/inst
python3 solution/solve.py /tmp/inst      # -> recovers d, prints H7CTF{test}
```
Validated across 10 fresh random instances (10/10 solved) and via the serving
path (spawn serve.py, download over HTTP, solve). The container itself is built
and verified by the importer (Cloud Build), per repo convention.

## Fairness / anti-agent notes
- Per-team dynamic flag: no flag-sharing, no handout-sharing.
- No nonce repeats and no bit bias: the textbook ECDSA reflexes (repeated-k, HNP,
  small-nonce lattice) all fail. The intended path is recognizing the recurrence
  and eliminating its unknown coefficients.
- A degree-1 (LCG) fit does not recover the key: the chain is genuinely degree 2,
  so a solver must sweep the recurrence degree.
- Flag sealing is fully specified in the brief, so decryption is unambiguous once
  `d` is found. The only difficulty is the crypto, not reversing a harness.
- The per-instance key is cryptographically random (`secrets`); never predictable.
- No general factoring, no external datasets, self-contained.
