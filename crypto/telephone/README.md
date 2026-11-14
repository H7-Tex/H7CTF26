# Broken Telephone

**Category:** crypto  **Difficulty:** insane  **Author:** abu

> Two boxes in a Halcyon mesh have been muttering at each other for months in a firmware dialect no upstream library will speak. You have a tap on the wire between them.
>
> Make the gateway hand over what only an operator is meant to see.

Handout: `handout/broken_telephone.zip` (`murmur_crypto.py` and the `MURMUR-1.2.md` protocol spec). Per-team TCP instance on port 1337.

## Solution

The service puts you in the middle of a live MURMUR link. A guest node and a gateway do a Noise `XKpsk3` handshake and then talk in transport frames. The gateway only releases the flag in reply to an admin PROVISION control frame, the node never sends one, and the transport keys come from an ephemeral-ephemeral DH. So there is nothing to replay and nothing to derive; we have to forge a frame from the wire alone.

First problem is just reading the traffic. Every frame's 2-byte length is XOR masked:

```
mask_i = LE16( BLAKE2s( h2 || "MURMUR-len" || LE32(i) ) )
```

The BLAKE2s in `murmur_crypto.py` is not stock. Its last round reuses the round 0 permutation, so `hashlib` or any Noise library gives you the wrong `h2` and you can't even find frame boundaries. Using the shipped primitive, we recompute `h2` from the public transcript (protocol name, gateway static key, both ephemerals, both handshake ciphertexts), regenerate the masks per direction and split both feeds into frames. Bodies also carry a random run of zero padding, so guessing lengths from the spec layouts doesn't work.

Once the frames are readable, track the ChaCha20-Poly1305 counter. The firmware bumps it for DATA frames but not CONTROL frames. The node opens with a few CONTROL keepalives and then a DATA telemetry frame, all at counter 0. Same `(key, nonce)` several times. The gateway does the same thing on its side.

Keepalive payloads are empty, so the plaintext is just zero padding and the ciphertext is the raw keystream for counter 0. That lets us encrypt anything, but the Poly1305 key lives in block 0 and is never exposed, so we still need to forge tags.

That is the Poly1305 forbidden attack. All colliding frames share one `(r, s)`:

```
tag = ( poly(r) + s ) mod 2^128
```

Subtracting two tag equations kills `s`, leaving a polynomial in `r` over `GF(2^130 - 5)` plus a small carry term `delta` in `-4..4`. For each `delta` we find roots (gcd with `x^p - x`, then Cantor-Zassenhaus), keep the ones that respect the Poly1305 clamp, and intersect across pairs. Identical keepalives need deduping first or a degenerate pair hides the root. Then `s` falls out of any single equation.

Forge the frame: payload `01 01 <len16> "READ_SECRET"`, XOR with the counter 0 keystream, tag it with `(r, s)`, mask the length with `mask_0` for the gateway's receive side and inject it as the gateway's first inbound frame. It is a CONTROL frame at counter 0, so the gateway accepts it without desyncing.

The gateway answers with a CONTROL frame at counter 1 (it already sent one telemetry frame). Its counter 1 keepalives gave us that keystream too, so XOR, strip padding, read the flag.

```
python3 solution/solve.py <host> <port>
```

Local:

```
FLAG='H7CTF{example}' PORT=1337 python3 challenge/server.py &
python3 solution/solve.py 127.0.0.1 1337
```

Flag is dynamic, per team. Keys, padding and flag are fresh every session, so nothing carries over between instances.
