# Broken Telephone - intended solve

Category: crypto. Difficulty: insane.

The service is a man in the middle tap on a live MURMUR link. A guest node and a
gateway complete a Noise `XKpsk3` handshake and then exchange transport frames.
The gateway holds the flag and releases it only in response to an authenticated
admin PROVISION control frame. The guest node never asks for provisioning, so
there is no admin frame to replay. The transport keys come from an
ephemeral-ephemeral DH, so a tap cannot derive them. The flag has to be won by
forging one control frame from the wire alone.

## 1. Speak the dialect (segment the wire)

Stock Noise stacks fail here on turn one. The 2 byte length prefix of every
transport frame is XOR masked with a keystream derived from the handshake hash:

```
mask_i = LE16( BLAKE2s( h2 || "MURMUR-len" || LE32(i) ) )
```

The BLAKE2s shipped in `murmur_crypto.py` is not stock BLAKE2s. Its message
schedule reuses the round 0 permutation on the final round, so every digest
differs from a reference implementation. A player who reaches for `hashlib` or a
Noise library computes the wrong `h2`, the wrong mask, and cannot even find
frame boundaries. Using the shipped primitive, recompute `h2` from the public
transcript (protocol name, gateway static public key, both ephemeral keys, the
two handshake ciphertexts), regenerate `mask_i` per direction, and segment both
byte feeds into typed frames. Frame bodies are further padded with a random run
of zero bytes, so the outer masked lengths cannot be guessed from the documented
layouts; the dialect BLAKE2s is the only way in.

## 2. Find the reused nonce

Track the ChaCha20-Poly1305 message counter per direction. The fielded firmware
advances the counter for DATA frames but not for CONTROL frames. The node opens
each session with several CONTROL keepalives and then a DATA telemetry frame,
all under counter 0. That is a set of AEAD messages sharing one `(key, nonce)`.
The gateway does the same on its side.

Keepalive payloads are empty, so their plaintext is only the zero padding. XOR a
keepalive ciphertext with zeros and you have recovered the ChaCha20 keystream
for that direction at counter 0. That keystream lets you encrypt a chosen frame,
but it does not reveal the Poly1305 one time key, which lives in ChaCha20 block
0 and is never used as message keystream.

## 3. Poly1305 forbidden attack

The colliding node frames at counter 0 all authenticate under the same one time
key `(r, s)`. For each frame the tag satisfies

```
tag = ( poly(r) + s ) mod 2^128
poly(r) = sum_j block_j * r^(L-j+1) mod (2^130 - 5)
```

where the blocks are the RFC 8439 MAC input `aad || pad16 || ct || pad16 ||
len(aad) || len(ct)`. Subtract two tag equations to cancel `s`:

```
poly_a(r) - poly_b(r) = (tag_a - tag_b) + delta * 2^128   (mod 2^130 - 5)
```

`delta` is the small difference of the `mod 2^128` carries, in `-4..4`. For each
`delta`, build the polynomial and find its roots over `GF(2^130 - 5)` (gcd with
`x^p - x`, then Cantor-Zassenhaus). Keep only roots that match the Poly1305
`r` clamp. With several colliding frames, the true `r` is the one root common to
every pair; recover `s` from any single equation and verify every tag. The
reference solver dedupes identical keepalives so a degenerate pair cannot hide
the root.

## 4. Forge and inject

Build the admin PROVISION control payload `01 01 <len16> "READ_SECRET"`, XOR it
with the recovered counter 0 keystream to get the ciphertext, and compute a valid
Poly1305 tag with `(r, s)`. Mask the length with `mask_0` for the gateway's
receive side and `inject` it as the gateway's first inbound frame. Because it is
a CONTROL frame at counter 0 the gateway authenticates it and does not desync.

## 5. Read the reply

The gateway answers with a CONTROL frame carrying the secret. Its send counter is
1 by then (it sent one telemetry frame at counter 0). Its counter 1 keepalives
already gave you the gateway to node keystream at counter 1, so XOR it out, strip
the padding, and read `H7CTF{...}`.

Everything is per session: fresh ephemeral keys, fresh pad lengths, and a per
team flag, so no capture, keystream, or forged frame transfers between instances.

## Running the reference solver

```
python3 solution/solve.py <host> <port>
```

Local:

```
FLAG='H7CTF{example}' PORT=1337 python3 challenge/server.py &
python3 solution/solve.py 127.0.0.1 1337
```
