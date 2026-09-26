# Vouchsafe - Design and Build Notes

Category: crypto. Difficulty: insane. Wire: HTTPS (Traefik) to a single Go binary.

## Concept

A hand-rolled WebAuthn / FIDO2 relying party (net/http, a small in-tree CBOR
decoder, stdlib `crypto/x509` and `encoding/asn1`). Deliberately not
`go-webauthn`, so the attestation-verification bug is ours. Reaching the
enterprise tier unlocks a privileged assertion that emits the per-team flag.

Two composed flaws, both required, reachable only together:

- **Bug A (trust-anchor confusion).** On the self-enroll branch (AAGUID not in
  the pinned MDS store) each `x5c` cert is verified against `x5c[0]` as anchor,
  and `x5c[0]` is never compared to any pinned root. A length-1 self-signed leaf
  is its own anchor.
- **Bug B (context-tag drift).** The enterprise policy extension's elevation flag
  is read from context tag `7 + aaguidCount`. The documented `[7]` flag is
  rejected if self-declared TRUE, so promotion requires shifting the read with
  `aaguidCount` and planting TRUE at the derived tag.

## Reviewer fixes applied

The design review flagged that shipping the full RP source collapses the
anti-agent premise, that the public seed ("attestedfun") is searchable, that the
difficulty risked being encoding friction, and that uniqueness had to be proven.
Applied:

1. **No server source in the handout.** Players receive the protocol spec, a
   correct reference client (the ceremony encoder), and the MDS blob. The
   trust-anchor and tag-drift behavior must be discovered black-box against the
   live service. The self-enroll branch and the policy schema are described; the
   flaws are not.
2. **Friction converted to insight.** The reference client ships a working
   CBOR / authData / COSE / assertion encoder that enrolls at standard tier, so
   byte-exact encoding is not the wall. The work is the two-bug reasoning.
3. **Split error surface.** Malformed CBOR / DER / JSON / base64 returns HTTP 400
   with a coarse component label; every semantic and trust failure returns a
   single uniform 403. Encoding hygiene is debuggable; the trust decision gives
   no oracle.
4. **Seed de-risked.** New extension OID (`1.3.6.1.4.1.61387.2.7.4`), renamed
   field (`elevated`), and different tag arithmetic (base 7, not the seed's 10),
   plus an explicit reject on a self-declared base-tag TRUE so the count shift is
   genuinely required rather than a one-line flag flip.
5. **Uniqueness harness.** `solution/uniqueness_check.py` drives the honeypot and
   decoy paths (no-x5c, benign policy, base-tag cheese, wrong-tag, known-AAGUID,
   tpm, android-key, negative/large counts) and asserts only the intended forge
   reaches enterprise.

## Anti-cheese / soundness

- The flag is read from `$FLAG` at startup, the env var is then unset, and it is
  emitted only by the enterprise assertion. No flag literal is in the binary,
  source, MDS blob, or spec.
- Per-instance, in-memory, session-keyed state. A forged credential from one team
  is worthless against another team's fresh nonces.
- Nonce binding on both ceremonies defeats replay of real or captured samples.
- Known-AAGUID and tpm / android-key paths require a chain to a pinned MDS root
  and are fixed at standard; they cannot be coerced to enterprise.
- `aaguidCount` is bounded (0..32) before it is used as a tag offset, so a large
  or negative count cannot panic or leak an oracle.
- Ledger metering: `/register/begin` and `/assert/begin` each cost a credit,
  capping blind iteration without a race.

## Build and validate

- Server: `challenge/server` (Go, stdlib only, offline build).
- Image: `Dockerfile` builds a static binary on `golang:1.22-alpine` and runs on
  `alpine:3.20` as a non-root user with the MDS blob baked in.
- Local validation is native (no Docker required):
  build the binary, run with `FLAG`, `MDS_PATH`, `RP_ID`, `ORIGIN`, then run
  `solution/solve.py` and `solution/uniqueness_check.py`.

## Deploy notes (Anvil)

Plain docker service, no special node pool, no GPU. Exposed as public HTTPS via
Traefik. Set `RP_ID` and `ORIGIN` to the instance hostname so `rpIdHash` and the
clientData origin check match. Inject the per-team `$FLAG`. `CREDITS` tunes the
Ledger budget per session.
