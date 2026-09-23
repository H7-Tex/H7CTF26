# Webhook: intended solution

Launch the instance, then:
```
python3 solution/solve.py http://<instance>/
```
Reads the captured webhook from `/sample`, forges a `role=owner` webhook by hash
length-extension, submits it, and prints this instance's per-team `H7CTF{...}`.

## Path
1. `GET /sample` gives a legitimate `(body, X-Signature)` where
   `X-Signature = SHA256(secret || body)` and `body` ends `...&role=guest`.
2. Recognize the MAC is `SHA256(secret || body)`, which is length-extendable
   (Merkle-Damgard). The `/v2` HMAC endpoint is the tempting dead end: HMAC is not
   extendable, so do not attack it.
3. You do not know `len(secret)`. For each candidate length L:
   - forge `new_body = body || md_pad(L + len(body)) || "&role=owner"` and the
     matching `new_sig` by resuming SHA-256 from the sample digest's state,
   - `POST /webhook` with the raw `new_body` and `X-Signature: new_sig`.
   The correct L verifies; the server parses `role=owner` (last-value-wins over the
   glue) and pays out the flag.

The reference solver ships a from-scratch SHA-256 that can resume from a given
digest state, so it needs no `hashpumpy`/`hash_extender`; players typically use
`hashpumpy` or `hash_extender` for the same effect.
