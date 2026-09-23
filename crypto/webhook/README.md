# Webhook

`crypto` / `medium` / on-demand per-team instance (docker, HTTP), dynamic flag.

A merchant webhook receiver that authenticates webhooks with
`X-Signature = SHA256(secret || body)`. Because SHA-256 is a Merkle-Damgard hash,
that construction is length-extendable: from one captured `(body, sig)` a player
forges a valid signature for `body || glue || "&role=owner"` without the secret
(the secret length is unknown, so it is brute-forced over a small range). A
`role=owner` webhook triggers the owner payout (the flag). The `/v2` endpoint uses
HMAC-SHA256 and is not extendable, i.e. the built-in "this is the fix" decoy.

Real basis: hash length-extension against `H(secret||message)` MACs (the classic
Flickr API signature bug and its many descendants).

## Delivery
Per-team live instance. Fresh random secret (random length) per team; the flag
(`$FLAG`, injected) is returned by `POST /webhook` only for a valid signature on a
`role=owner` body.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/app.py` : the receiver (SHA-256 v1, HMAC v2 decoy, `/sample`). stdlib only.
- `challenge/Dockerfile` : the instance image (`h7ctf26/webhook`).
- `solution/solve.py` : reference solver (self-contained SHA-256 with resumable
  state for the length extension; brute the secret length; forge). No `hashpumpy`.
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080     # -> forges role=owner, prints the flag
```
The solver's SHA-256 + length-extension was checked against `hashlib` over 400
random cases; the full forge path passes 6/6 across random secret lengths.

## Fairness / anti-agent notes
- Per-team dynamic flag; per-team random secret and secret length.
- The classic mistake framed as a real product: `SHA256(secret||body)` MAC vs the
  correct HMAC (`/v2`), so the fix is visible and the bug is the point.
- The secret length is the only search, over a small range (about 40); no guessing.
- Standard signature verification server-side; the difficulty is the crypto.
