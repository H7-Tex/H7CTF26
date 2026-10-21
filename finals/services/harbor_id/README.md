# Harbor ID

City SSO platform with passkey authentication and a crew portal.
Two containers: IdP (port 7001) and Crew Portal (port 7011).

Stack: TypeScript / Node 24 / Fastify / SQLite, no compile step (`--experimental-strip-types`).

---

## Flag stores

| Store | Location | Advisory |
|-------|----------|---------|
| 0 | Crew handover notes on the Portal board | The Portal's SSO endpoint links accounts by a mutable token field instead of the IdP's stable identity pair. |
| 1 | Break-glass note in the IdP user record | The WebAuthn login ceremony trusts a client-supplied identity field without verifying it matches the authenticating credential. |

---

## Bugs

### Store 0 (crew notes)

**V1 - nOAuth (E)**: `service/portal/src/routes/sso.ts` line 44.
Portal looks up accounts with `WHERE email = ?` instead of `WHERE idp_iss = ? AND idp_sub = ?`.
An attacker registers a fresh IdP account, changes its email to the victim's via `PATCH /account/email`,
gets an id_token, and SSOs into the Portal as the victim (CVE class: Grafana CVE-2023-3128 / nOAuth).

**V2 - OIDC claims echo (M)**: `service/idp/src/routes/oidc.ts` lines 107-112.
The IdP echoes the `value` field from the OIDC claims parameter directly into the id_token for any
claim not in the user-sourced allowlist. An attacker requests `crew: {value: "Victim Crew Name"}`,
gets that crew in their token, SSOs into Portal, and reads the flag from the victim's crew board.

### Store 1 (break-glass note)

**V1 - userHandle not checked (M)**: `service/idp/src/routes/webauthn.ts` lines 210-216.
`login/finish` decodes the client-supplied `userHandle` and uses it as the logged-in user identity
without verifying it matches `cred.user_id`. An attacker signs with their own credential but sets
`userHandle` to the victim's sub (obtainable via `/.well-known/webfinger`), bypassing authentication.

**V2 - ceremony not session-bound (M)**: `service/idp/src/routes/webauthn.ts` line 68.
`register/finish` uses `body.user_id ?? chal.user_id` instead of always using `chal.user_id`.
An attacker begins a registration ceremony as themselves, then submits a `user_id` pointing to the
victim in the finish call, registering their credential against the victim's account.

---

## Checker error codes

| Code | Meaning |
|------|---------|
| HARBORID-REG-01 | IdP /register rejected |
| HARBORID-REG-02 | /register returned no bootstrap_token |
| HARBORID-PASS-01 | Passkey registration failed |
| HARBORID-AUTH-01 | Passkey authentication failed |
| HARBORID-CREW-01 | Crew creation failed |
| HARBORID-MEM-01 | Crew membership add failed |
| HARBORID-TOKEN-01 | id_token request failed |
| HARBORID-SSO-01 | Portal SSO failed |
| HARBORID-BOARD-01 | Portal crew board read failed or flag missing |
| HARBORID-NOTE-01 | Crew note post failed |
| HARBORID-ACCT-01 | IdP /account read failed |
| HARBORID-ACCT-02 | break_glass_note not found in account |
| HARBORID-WF-01 | Webfinger lookup failed |
| HARBORID-DEVK-01 | Device JWKS publish/fetch failed |

---

## Patches

| File | What it does | Expected outcome |
|------|-------------|-----------------|
| `patches/store0_v1_correct.patch` | Portal: look up by (iss, sub) | exploit 0 + 2 fail |
| `patches/store0_v1_wrong.patch` | Portal: validates email is present (no fix) | checker breaks |
| `patches/store0_v2_correct.patch` | IdP: remove claims-value echo | exploit 2 fails |
| `patches/store0_v2_wrong.patch` | IdP: length/regex check on echoed value (still echoes) | checker breaks |
| `patches/store1_v1_correct.patch` | IdP login: assert userHandle === cred.user_id | exploit 1 fails |
| `patches/store1_v1_wrong.patch` | IdP login: require userHandle (breaks usernameless) | checker breaks |
| `patches/store1_v2_correct.patch` | IdP register: ignore body.user_id, use chal.user_id | exploit 3 fails |
| `patches/store1_v2_wrong.patch` | IdP register: require body.user_id to be present (still trusts it) | checker breaks |

---

## Standalone exploits

- `exploits/store0_nooauth.py` - nOAuth email account takeover (V1)
- `exploits/store1_userhandle.py` - WebAuthn userHandle impersonation (V1)

Run from repo root: `python3 exploits/store0_nooauth.py <host> <email> <crew>`.
Both depend on `checker/harborkey.py` for WebAuthn ceremonies.

---

## Unintended bugs / anti-cheese

- `/directory` leaks all usernames and emails publicly - this is intentional (game mechanic for nOAuth).
- `/.well-known/webfinger` leaks user subs - intentional (required for ceremony-hijack exploit).
- Crew notes are not encrypted at rest - out of scope for this challenge.
- Session tokens are high-entropy random; no brute-force path.
- Flag field (`break_glass_note`) is write-once on registration; no update endpoint exists.
