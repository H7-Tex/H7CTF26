# Hill C -- Harbor Master

King-of-the-Hill on the Dockyard registry. The crown is a manifest annotation on
`harbor/throne:latest`. Control the throne across reset cycles to score points.

Port: 8085 (harbor-master sidecar). Dockyard registry: 7005.

Window: Sun 07:00-12:00 IST.

---

## Crown mechanic

The KotH engine polls `GET /koth/status` (unauthenticated):

```json
{"holder": "<team-tag>|null", "since": <unix>}
```

To claim the crown, push a manifest to `harbor/throne:latest` with annotation
`h7.crown=<HMAC(rpc_secret, round || tag)>`. The sidecar decodes the HMAC via
`KOTH_VERIFY_URL` to resolve the team tag.

`POST /koth/reset` (Bearer KOTH_ADMIN_TOKEN) clears the throne each round.

`GET /koth/info` returns door states and the throne repo name.

---

## Doors (D1-D4)

Each door is an authz bug in the embedded Dockyard registry. The round controller
enables N=4 doors per round by setting the corresponding `VULN_*` env vars.
The king may lock at most 2 doors it has walked through (using the door token from
`/koth/info`).

---

### D1 -- comma-split scope (shared with S5 bug V2 store A)

**Component:** `registry.CheckAccess`
**Advisory:** The token scope name is split on comma to simulate multi-repo CI tokens.
A token requested for `harbor/junk,harbor/throne:push` grants push on both repos.
**Attack:** Register attacker, create junk repo, request scope
`repository:attacker/junk,harbor/throne:push`, push crown manifest.
**Correct patch:** Remove the `strings.Split(a.Name, ",")` -- use exact name match only.
**Wrong patch:** Reject scopes containing the literal string "harbor" -- the checker's
noise variant requests tokens for repos named `harbor-stats` and `harbor-metrics`, which
are legitimate multi-segment names; blocking them breaks the checker.

---

### D2 -- webhook template leaks DEPLOY_KEY (shared with S5 bug V1 store B)

**Component:** `api.fireWatch` / `RepoView`
**Advisory:** When VULN_D2 is set, `RepoView.Secrets` is populated with repo secrets
before template rendering. A watch on `harbor/throne` with template `{{.Secrets.DEPLOY_KEY}}`
extracts the harbor admin's deploy credential on every push.
**Attack:** Create a watch on the public `harbor/throne` repo with the leaking template.
A test delivery fires immediately on watch creation. Read the DEPLOY_KEY from deliveries.
Use it to authenticate as the harbor admin and push a crown manifest.
**Correct patch:** Remove `Secrets` from `RepoView` (or do not populate it in `fireWatch`).
**Wrong patch:** Rate-limiting watch creation -- the attacker creates one watch and reads
the delivery immediately; one watch is sufficient to extract the key.

---

### D3 -- manifest PUT skips push auth when all blobs are linked (hill-only)

**Component:** `api.handleManifest` (PUT case)
**Advisory:** When all blobs referenced in the manifest body are already linked to the
target repo, push auth is skipped entirely. The "all blobs linked" condition is a proxy
for trust -- but the auth gate is missing. The empty config blob
(`sha256:44136fa355ba77b9ad7b35f1a80f6b8bb480e88a82b4d5e0a1c487a1fefa7e6b`) is always
linked to `harbor/throne` after initialization, so no prior blob upload is needed.
**Attack:**
1. Construct a minimal manifest with `config.digest = sha256:44136fa...` (well-known
   empty blob, always linked), `layers: []`, `annotations: {"h7.crown": <team-tag>}`.
2. PUT to `/v2/harbor/throne/manifests/latest` with no Authorization header.
3. D3 bypass fires: empty blob is linked to harbor/throne -- auth skipped. Crown set.
**Correct patch:** Always require push auth regardless of blob link state.
**Wrong patch:** Require a valid (but unchecked) Bearer token -- the attacker supplies
any token string and the bypass still fires.

---

### D4 -- case-variant repo name (hill-only)

**Component:** `api.handleManifest` (PUT case, storage normalization)
**Advisory:** Auth check uses the raw repo name from the URL. Storage normalizes to
lowercase after auth passes. A user named `HARBOR` can request push scope for
`HARBOR/throne` -- `canAccess` finds no row for `HARBOR/throne` in the DB, so the
no-repo fallback (`parts[0] == user`) grants it. The manifest is then stored under
`harbor/throne` (lowercased), overwriting the throne.
**Attack:**
1. Register username `HARBOR` (any capitalization of `harbor`).
2. Get push token for `HARBOR/throne`.
3. PUT manifest to `/v2/HARBOR/throne/manifests/latest` with `h7.crown` annotation.
4. Auth passes (token scope `HARBOR/throne` matches). Storage normalizes to
   `harbor/throne`. Crown set.
**Correct patch:** Normalize repo name to lowercase BEFORE the auth check.
**Wrong patch:** Case-fold usernames on registration (HARBOR -> harbor conflicts with
existing harbor admin, returns an error the checker sees as MUMBLE during setup).

---

## Reset behavior

`POST /koth/reset` (Bearer KOTH_ADMIN_TOKEN):
1. Push a clean manifest to `harbor/throne:latest` with empty annotations.
2. The harbor-master sidecar refreshes its admin token and re-initializes the throne.

After reset the throne has no `h7.crown` annotation -- `/koth/status` returns
`{"holder": null, "since": 0}`.

The Dockyard DB is not wiped between rounds. Blob links and token grants persist,
so blobs mounted in a previous round stay accessible (this is intentional -- teams
that already walked through a door keep their blob).

---

## Checker exception codes

| Code | Feature |
|---|---|
| HARBOR-INIT-01 | dockyard did not come up within timeout |
| HARBOR-INIT-02 | admin registration failed |
| HARBOR-INIT-03 | throne repo creation failed |
| HARBOR-STATUS-01 | /koth/status returned non-200 |
| HARBOR-STATUS-02 | /koth/status JSON parse error |
| HARBOR-RESET-01 | /koth/reset rejected (bad token or 5xx) |
| HARBOR-RESET-02 | throne still has crown after reset |

---

## Unintended bug notes

- `canAccess` grants push to `user/anything` when the repo does not exist, regardless of
  capitalization. This is intentional (users own their namespace). D4 exploits the gap
  between this grant and the storage normalization. Patching D4 by blocking repo creation
  in mixed case is wrong -- the checker creates repos like `harbor-stats` (lowercase with
  hyphen), not mixed case.
- `harbor/throne` is public (pull = open). This is intentional: any team can read the
  current crown manifest to confirm their push landed. The crown annotation itself is
  the HMAC token, not the raw team tag, so reading it gives no information advantage.
- The empty config blob (`sha256:44136fa...`) is pinned in the genesis manifest. Its
  digest is well-known (sha256 of `{}`). D3 exploits use it as the config blob to
  avoid needing to upload any content.
