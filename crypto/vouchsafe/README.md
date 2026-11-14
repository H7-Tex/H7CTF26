# Vouchsafe

**Category:** crypto  **Difficulty:** hard  **Author:** abu

> H7 Passport is our passwordless SSO. Staff tap a passkey and they are in. The admin console behind it only opens for enterprise-attested authenticators, the corporate hardware the portal already trusts.
>
> Open the admin console.

Handout: `handout/vouchsafe-handout.zip` (`SPEC.md`, `passport_client.py`, `mds_blob.json`). No server source. Per-team HTTP instance on port 8080, a hand-rolled WebAuthn relying party in Go.

## Solution

The reference client does a normal consumer passkey enrollment (`packed` self-attestation, no `x5c`) and lands at `standard` tier. `/assert/finish` then tells you the console needs an enterprise-attested authenticator. The client already gets all the CBOR/authData/COSE encoding right, so encoding isn't the wall; the trust logic is.

Two things in the spec matter. Authenticators whose AAGUID is in the MDS blob get a real chain check up to the pinned MDS root, and real devices never carry the enterprise policy extension, so that path always ends at `standard`. It returns 200 "enrolled" and goes nowhere. Then there's a legacy self-enroll path for AAGUIDs not in the blob, and an `AuthenticatorPolicy` extension whose parser was "refactored" from positional decoding to context tags.

Bug A, self-anchored chain. On the self-enroll path every cert in `x5c` is checked against `x5c[0]`, and `x5c[0]` is never compared to a pinned root. A single self-signed leaf is its own anchor. Pick an AAGUID that's not in the blob (all zeros works) and the leaf key can just be the credential key.

Bug B, tag drift. Enterprise tier needs the leaf to carry extension `1.3.6.1.4.1.61387.2.7.4`:

```
AuthenticatorPolicy ::= SEQUENCE {
    version       INTEGER,
    aaguidCount   INTEGER,
    aaguids       SEQUENCE OF OCTET STRING,
    elevated  [7] BOOLEAN OPTIONAL,
    ...
}
```

`[7] TRUE` is rejected outright as self-declared elevation. But the parser reads the elevation flag from tag `7 + aaguidCount`. Set `aaguidCount = 1` with one dummy 16-byte AAGUID, put `[7] FALSE` where the spec says, and `[8] TRUE` where the parser actually looks.

The ceremony:

1. `GET /register/begin` for a challenge.
2. Make a P-256 key and a self-signed leaf with the policy extension above.
3. Build `authData` with AT+UP+UV, the unknown AAGUID, a credential id and the COSE key.
4. Sign `authData || SHA256(clientDataJSON)` and send `{fmt: "packed", attStmt: {alg: -7, sig, x5c: [leaf]}, authData}` to `/register/finish`. It's stored as `enterprise`.
5. `GET /assert/begin`, sign the assertion with the same key (UV set), `POST /assert/finish`, get the flag.

Everything is bound to fresh per-session challenges, so replaying captured samples doesn't work. `tpm` and `android-key` also need a pinned root and never reach enterprise. Malformed input gets a 400 with a coarse hint, but every trust failure is the same 403, so there's no oracle for the trust decision. `/register/begin` and `/assert/begin` each cost a credit (`CREDITS`, 80 in the Docker image), so blind fuzzing runs out fast.

```
python3 solution/solve.py http://<instance>
python3 solution/uniqueness.py http://<instance>
```

`uniqueness.py` throws the decoys at the server (no x5c, `[7] TRUE`, wrong tag, known AAGUID, tpm, android-key, bad counts) and checks only the intended forge gets to enterprise.

Local: build `challenge/server` with Go (stdlib only), run it with `FLAG`, `MDS_PATH`, `RP_ID` and `ORIGIN` set, then point the scripts at it. When deploying, `RP_ID` and `ORIGIN` must match the instance hostname or the `rpIdHash` and origin checks fail.

Flag is dynamic, per team.
