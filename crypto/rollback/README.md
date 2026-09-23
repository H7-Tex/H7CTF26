# Rollback

`crypto` / `hard` / on-demand per-team instance (docker, HTTP), dynamic flag.

An LMS/WOTS+ hash-based firmware signer (RFC 8554 in spirit). Hash-based signatures
are stateful: each one-time WOTS+ leaf must sign exactly once. A maintenance
"rollback" endpoint resets the signing counter, so a leaf can be reused. Across
enough reused signatures on the same leaf, each Winternitz chain position leaks its
value at the lowest signed digit (usually the raw secret at digit 0), which lets you
forge a WOTS+ signature for a chosen backdoored firmware. The Merkle auth path is
unchanged, so the forgery verifies against the device root and the device boots it.

Real basis: the operational footgun of stateful hash-based signatures (LMS/XMSS
one-time-key reuse; NIST SP 800-208 warns about exactly counter reuse).

## Delivery
Per-team live instance. Fresh random LMS key per team. The signer refuses to
notarize a build containing the backdoor marker, so you must forge; the device
returns the flag (`$FLAG`, injected) when it boots a verifying backdoored build.

## Endpoints
- `GET /root` : the device trust anchor (Merkle root).
- `POST /sign {firmware}` : notarize a benign build (backdoored builds refused). Advances the counter.
- `POST /rollback` : resets the signing counter (the bug).
- `POST /deploy {firmware, sig}` : boots anything that verifies against the root.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080, provides `lms.py`).
- `challenge/lms.py` : the signing scheme (WOTS+ over a Merkle tree). Shipped to players.
- `challenge/app.py` : the notary + device service.
- `challenge/Dockerfile` : the instance image (`h7ctf26/rollback`). stdlib only.
- `solution/solve.py` : reference solver (reuse leaf 0, recover key, forge, deploy).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080      # -> forges a backdoored build, prints the flag
```
De-risked: the scheme's sign/verify round-trips and rejects tampering; the reuse
forgery is feasible (about 160 reused signatures recover nearly every chain
position, then a single grind forges). Full path validated 3/3 across random
instances. The container is built/verified by the importer (Cloud Build).

## Fairness / anti-agent notes
- Per-team dynamic flag; per-team random LMS key.
- The scheme (`lms.py`) is shipped: the difficulty is recognizing that the counter
  reset re-enables one-time-key reuse and doing the WOTS+ forgery, not reversing a harness.
- Feasible by construction (many reuses -> chain positions recovered), not a lucky grind.
- Realistic PQC: this is the documented operational failure mode of stateful
  hash-based signatures, not a contrived bug.
