# Vouchsafe - Intended Solution

## Summary

H7 Passport is a hand-rolled WebAuthn / FIDO2 relying party. The admin console
behind `/assert/finish` only runs for credentials enrolled at the **enterprise**
tier. The intended solve forges a self-enrolled attestation that the RP promotes
to enterprise by chaining two independent flaws, then completes a live
register-then-assert ceremony over fresh server nonces.

Nothing static yields the flag. The per-team flag lives only in process memory
and is emitted solely by the enterprise-gated privileged action after a valid
live assertion.

## Recon

The handout is the protocol spec, a working reference client that performs a
plain consumer-passkey enrollment (fmt `packed` self-attestation, no `x5c`), and
the frozen MDS3 blob. The reference client demonstrates the full ceremony
(clientDataJSON, authData layout, COSE EC2 key, CBOR attestationObject, the
assertion signature), so encoding is not the barrier. Running it enrolls at
`standard` tier and `/assert/finish` then reports the console needs an
enterprise-attested authenticator.

Two facts from the spec matter:

1. Known authenticators (AAGUID present in the MDS blob) are verified by building
   the attestation chain up to the pinned MDS root. Real authenticators never
   carry the enterprise policy extension, and this path deterministically lands
   at `standard`. It is a honeypot: a 200 "enrolled" that can never reach the
   enterprise gate.
2. There is a legacy self-enrolled path for authenticators whose AAGUID is not in
   the MDS store, plus an `AuthenticatorPolicy` extension whose parser was
   refactored from positional decoding to context-tag numbering.

## Bug A: self-anchored chain on the self-enroll path

On the self-enroll branch (unknown AAGUID) the RP validates the `x5c` list by
requiring every certificate to be signed by `x5c[0]`, and never compares `x5c[0]`
to any pinned MDS root. A length-1, self-signed leaf therefore satisfies the loop
against itself and becomes its own trust anchor. The attacker controls this key,
so it can equal the credential (COSE) key.

This is only reachable when the AAGUID is not in the MDS blob, which is why the
exhaustive blob matters: you pick an AAGUID (all-zero works) that is not listed.

## Bug B: privileged flag read from a count-derived context tag

Enterprise tier requires the leaf to carry the policy extension
`1.3.6.1.4.1.61387.2.7.4`:

```
AuthenticatorPolicy ::= SEQUENCE {
    version       INTEGER,
    aaguidCount   INTEGER,
    aaguids       SEQUENCE OF OCTET STRING,
    elevated  [7] BOOLEAN OPTIONAL,
    ...
}
```

The parser derives the tag it consults for the elevation flag as
`7 + aaguidCount`. The documented `elevated` field sits at `[7]`; a value of TRUE
there is explicitly rejected as a self-declared elevation, so you cannot simply
flip the documented flag. Setting `aaguidCount = 1` (with one dummy 16-byte
entry in `aaguids`) shifts the authoritative read to `[8]`. Place a benign
`[7] BOOLEAN FALSE` in plain sight and a `[8] BOOLEAN TRUE` where the parser now
looks, and the credential is stored at `enterprise`.

The count-derived tag is what makes this necessary rather than a one-line flag
flip, and it composes with Bug A: the elevation is only consulted on the
self-enroll branch, which only accepts certificates because of the self-anchor.

## Forge and ceremony

1. `GET /register/begin` for a fresh 32-byte challenge.
2. Generate an EC P-256 key. Build a self-signed leaf carrying the crafted policy
   extension (`aaguidCount=1`, `[7] FALSE`, `[8] TRUE`).
3. Build `authData` with AT+UP+UV flags, an unknown AAGUID, a credential id and
   the COSE form of the same public key.
4. Sign `authData || SHA256(clientDataJSON)` with the private key. CBOR-encode
   `{fmt:"packed", attStmt:{alg:-7, sig, x5c:[leaf]}, authData}`.
5. `POST /register/finish`. Bug A accepts the self-anchored leaf; Bug B reads
   `elevated=TRUE`; the credential is stored at `enterprise`.
6. `GET /assert/begin` for a fresh nonce. Sign `authenticatorData(UV set) ||
   SHA256(clientDataJSON)` with the same key.
7. `POST /assert/finish`. The server verifies the assertion against the stored
   COSE key, confirms `tier == enterprise` and UV, and returns the flag.

## Why replay and the decoys fail

- Every attestation and assertion is bound to a fresh per-session challenge, so a
  captured real sample or a replayed forgery fails nonce binding.
- The known-AAGUID path builds a real chain to a pinned root and is fixed at
  `standard`; forging it would require an MDS root private key.
- `tpm` and `android-key` also require a chain to a pinned root and never grant
  enterprise.

## Reference solver

`solution/solve.py` performs the full attack and prints the recovered flag.
`solution/uniqueness_check.py` exercises the honeypot and decoy paths and
confirms only the intended forge reaches enterprise.

Recovered during local validation:

```
RECOVERED FLAG: H7CTF{v0uchs4fe_self_anchor_tag_drift_9f3a}
```
(local test flag; production injects a per-team flag via `$FLAG`.)
