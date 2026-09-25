# Public Domain — deploy runbook (atom)

Live on atom behind the existing cloudflared tunnel `f420a248`. Flag `H7CTF{4fb846630ae38a205b}`
lives only in the WKD-served PGP key's UID (nothing to download; Anvil holds the static flag).

## 1. DNS (done by Abu — all proxied CNAME -> the tunnel)
```
clearpane.abu.rocks            CNAME f420a248-...cfargotunnel.com  (proxied)
cdn-static-3.abu.rocks         CNAME f420a248-...cfargotunnel.com  (proxied)
openpgpkey.abu.rocks           CNAME f420a248-...cfargotunnel.com  (proxied)
halcyon-strategies.h7tex.com   CNAME f420a248-...cfargotunnel.com  (proxied)
```

## 2. Site content
`challenge/sites/<host>/` -> `/var/www/public_domain/<host>/` (owned www-data). Includes the shared
favicon (identical across hosts), `cdn-static-3/site.css` (leak comment) + `m.js` (analytics
`PA-9F3C71E8`), `halcyon-strategies/.well-known/security.txt`, and the WKD tree under
`openpgpkey/.well-known/openpgpkey/abu.rocks/{policy,hu/<hash>}`.

## 3. nginx
Install `challenge/deploy/nginx-public_domain.conf` to `sites-available/` + symlink `sites-enabled/`;
`nginx -t && systemctl reload nginx`. The openpgpkey vhost serves the WKD path as
`application/octet-stream` with `Access-Control-Allow-Origin: *`.

## 4. cloudflared ingress
Add the four hostnames to `/etc/cloudflared/config.yml` ingress -> `http://localhost:80` (before the
`http_status:404` catch-all); `cloudflared tunnel ingress validate` then `systemctl restart cloudflared`.

## 5. Certificate Transparency (the hop-1 enabler)
Cloudflare serves a wildcard `*.abu.rocks`, which hides subdomain names from CT. Issue a named LE
cert so `clearpane` + `cdn-static-3` appear in CT (issuance alone logs them; the cert is NOT served):
```
certbot certonly --webroot -w /var/www/public_domain/clearpane -d clearpane.abu.rocks \
  -w /var/www/public_domain/cdn-static-3 -d cdn-static-3.abu.rocks --cert-name public_domain-ct
```
Indexers (crt.sh/certspotter) pick up new certs within ~15 min–few hours. Do NOT issue any cert for
`halcyon-strategies.h7tex.com` — it must stay out of h7tex.com CT enumeration (reached only via the
in-chain pointer).

## 6. Regenerating artifacts
- favicon + Shodan hash: `python3 challenge/make_favicon.py` (hash 630558264).
- PGP key (flag in UID `Curator (H7CTF{...}) <curator@abu.rocks>`): gpg batch keygen; WKD hash from
  `gpg --with-wkd-hash`; `gpg --export` -> `hu/<hash>` (see `challenge/pgp/`).

## 7. Verify
`python3 solution/solve.py` walks CT -> CDN leak + favicon -> security.txt -> WKD -> flag.
