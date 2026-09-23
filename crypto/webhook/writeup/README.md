# Webhook: writeup

## The setup
OrionPay signs each webhook it delivers as `X-Signature = SHA256(secret || body)`
and your merchant endpoint trusts that signature. A webhook whose body contains
`role=owner` authorizes an owner-only payout. You have one captured legitimate
webhook (`GET /sample`) but not the secret.

## The bug
SHA-256 is a Merkle-Damgard hash: its output is its full internal state after
absorbing the (padded) message. So given `H(secret || body)` and `len(secret||body)`,
you can *resume* hashing from that state and compute

    H(secret || body || glue || suffix)

for any `suffix`, where `glue` is the SHA-256 padding of `secret || body`, all
**without knowing the secret**. This is why a raw `H(key || message)` MAC is
broken and why HMAC exists. The `/v2` endpoint uses HMAC-SHA256, which is not
length-extendable, and is there as the deliberate dead end.

## The attack
1. From `/sample`: `body`, `sig = SHA256(secret || body)`.
2. You do not know `len(secret)`, so sweep it. For each candidate `L`:
   - `glue = md_pad(L + len(body))` (`0x80`, zero padding, then the 64-bit bit
     length of `secret || body`),
   - resume SHA-256 from `sig`'s state, having "already absorbed"
     `L + len(body) + len(glue)` bytes (block aligned), and hash the suffix
     `"&role=owner"` to get `new_sig`,
   - `new_body = body || glue || "&role=owner"`.
   - `POST /webhook` with raw `new_body` and `X-Signature: new_sig`.
3. The correct `L` produces a signature the server accepts. The server parses the
   body last-value-wins, so `role=owner` (a clean trailing parameter appended after
   the glue) overrides the original `role=guest`, and the owner payout returns the
   flag. The glue bytes land inside the previous parameter's value, so they do not
   disturb the appended `role=owner`.

Secret lengths in this challenge are ~10-20 bytes, well inside the swept range.

## Fix (shown in-challenge)
Use HMAC (`/v2`). HMAC's nested construction is not length-extendable, so the same
forge fails against it. That contrast is the lesson.

## Notes
- Players usually use `hashpumpy` or Ron Bowes' `hash_extender`; the reference
  solver implements a resumable SHA-256 directly so it depends only on the stdlib.
- Real basis: length-extension against `H(secret||message)` signatures (the Flickr
  API signature-forgery bug and its many descendants).
