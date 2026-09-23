# Shared Blood

`crypto` / `medium` / on-demand per-team instance (docker, HTTP), dynamic flag.

An IP-camera cloud whose device RSA keys were generated with a weak RNG, so two
devices in the fleet share a prime factor. No single key is weak; the weakness is
relational. A GCD of the target device's modulus against the rest of the fleet
reveals the shared prime and factors the target key. That key decrypts an
intercepted provisioning payload (RSA/PKCS1v1.5) carrying the admin bootstrap
token, which unlocks the camera console (the flag).

Real basis: "Mining your Ps and Qs" (Heninger et al., USENIX 2012), shared RSA
primes from low-entropy key generation on embedded devices.

## Delivery
Per-team live instance. Fresh per-team fleet with one shared-prime pair, a per-team
admin token RSA-encrypted to the target device, and the flag (`$FLAG`, injected)
returned by `POST /admin` on the correct token.

## Endpoints
- `GET /fleet` : device certs (public moduli + e).
- `GET /captured` : one intercepted provisioning payload (target serial + ciphertext).
- `POST /admin {token}` : the recovered admin bootstrap token returns the flag.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/app.py` : the camera cloud (fleet gen with a shared prime, token seal, console).
- `challenge/Dockerfile` : the instance image (`h7ctf26/shared-blood`); pycryptodome + gmpy2.
- `solution/solve.py` : reference solver (batch-GCD, factor, decrypt, log in).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080     # -> factors, decrypts, prints the flag
```
Validated 3/3 across random instances (batch-GCD finds the shared prime, the token
decrypts, the console unlocks). The container is built/verified by the importer.

## Fairness / anti-agent notes
- Per-team dynamic flag; per-team fleet with a fresh shared-prime pair.
- No single key is individually weak (no small factor, no Fermat-close primes on
  the target alone): the intended path is the cross-fleet GCD, not a per-key attack.
- 1024-bit device keys are realistically weak for embedded IoT; batch-GCD is the
  real technique for this failure mode.
- The captured payload names its target device, so there is no guessing which key.
