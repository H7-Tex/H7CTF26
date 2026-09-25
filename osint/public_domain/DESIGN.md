# Public Domain — design + build plan (OSINT, hard)  [dir: osint/public_domain, ex-Glasshouse]

Infrastructure-attribution investigation on our own consenting infra (abu.rocks + h7tex.com =
GREEN). Two web fronts that present as unrelated are secretly one operator; prove the link through
technical fingerprints only, then recover the operator's identity for the flag. No Shodan account
needed (self-contained); real Certificate Transparency on our domains is the one live-data hop.

## Design rules (locked with Abu)
- **Brief = ONE vague sentence.** It names NO domain at all (not abu.rocks, not h7tex.com), no
  hostname, no technique -- it only hints at *domains / infrastructure*.
- **The author field is `Abu`, and that IS the entry breadcrumb.** Everyone knows Abu, so players
  pivot from the author to his domains (abu.rocks) and into crt.sh. The nudge points at domains,
  not people, to keep them on the chain and out of the personal rabbit holes.
- **abu.rocks = entry side** (personal domain; safe for players to crt.sh-enumerate). **h7tex.com =
  the hidden second face**, surfaced ONLY via a direct in-chain pointer so players never enumerate
  h7tex.com and PRODUCTION STAYS UNTOUCHED. Only one challenge host lives on h7tex.com.
- **DNS: Abu adds ALL FOUR records himself** (the atom cloudflared tunnel may be linked to
  specifics he wants to control). I do NOT self-serve any DNS.

## Narrative
`ClearPane` is a scrappy transparency/whistleblower site claiming to be independent (no owner, no
agenda). You suspect it is secretly run by the same operator as `Halcyon Strategies`, a corporate
reputation-management (astroturf) firm on a different domain -- which would discredit it. Prove the
link with infrastructure fingerprints, then unmask the operator.

## The chain (4 hops)
- **Entry (discovered, nudged by "abu.rocks"):** crt.sh-enumerate `abu.rocks`; `clearpane.abu.rocks`
  (the transparency site) and `cdn-static-3.abu.rocks` (its asset host) stand out among the certs.
- **Hop 1 - Certificate Transparency (crt.sh):** real CT data on abu.rocks reveals the two hosts.
- **Hop 2 - favicon MurmurHash3 + discovery (h7tex.com surfaces HERE, via pointer only):**
  `cdn-static-3` carries a stray reference (HTML comment / mis-served config) to
  `halcyon-strategies.h7tex.com`; the identical custom favicon (same Shodan-style mmh3 hash) on both
  fronts confirms one operator. Player goes straight to that one host -- no h7tex.com enumeration.
- **Hop 3 - shared operator tell -> PGP:** `halcyon-strategies.h7tex.com` embeds the same
  self-hosted analytics site-ID as `clearpane` (the Bellingcat classic, corroboration) and
  references the operator's PGP: `curator@abu.rocks`, "verify our briefs via WKD." The email domain
  (abu.rocks = ClearPane's own domain) is the smoking gun linking the astroturf firm back to the
  leak site.
- **Hop 4 - WKD -> flag:** fetch the key via Web Key Directory from `openpgpkey.abu.rocks`
  (`/.well-known/openpgpkey/hu/<zbase32(sha1(localpart))>`); `gpg --show-keys` -> the UID comment
  is the flag.

## Flag
`H7CTF{4fb846630ae38a205b}` (random) -- lives only in the WKD-served PGP key's UID.

## Player-facing brief (ONE sentence -- NO domain named at all; only a "domains" hint; author=Abu = the breadcrumb)
author: `Abu` (the entry breadcrumb -- players know Abu -> pivot to his domains)
name: `Public Domain` (renamed from Glasshouse per Abu, 2026-09-25)
description (LOCKED): **Some operators still think their domains are private.**
sub_description: same one-liner (terse, per the v0.0.86 stoic pass -- no hints).

## Hosts / DNS (all proxied CNAME -> f420a248-aff3-4f6a-b596-4ba582dcb0cb.cfargotunnel.com)
All single-level under the apex so Cloudflare Universal SSL (`*.abu.rocks`, `*.h7tex.com`) covers
HTTPS and auto-logs certs to CT (makes hop 1 work; no manual certbot needed).
- `clearpane.abu.rocks`          (abu.rocks) - public front / entry
- `cdn-static-3.abu.rocks`       (abu.rocks) - asset/staging host
- `openpgpkey.abu.rocks`         (abu.rocks) - WKD host
- `halcyon-strategies.h7tex.com` (h7tex.com) - hidden operator front [1 host]

DNS: **Abu adds ALL FOUR records himself** (he controls the tunnel linkage). I self-serve none.
All are proxied CNAME -> the tunnel.

## Deploy (atom)
- nginx vhost per host (static roots under `/var/www/glasshouse/<host>`), server_name routing.
- add the four hostnames to `/etc/cloudflared/config.yml` ingress -> `http://localhost:80`
  (before the 404 fallback), restart `cloudflared.service`.
- HTTPS + CT entries come free from CF Universal SSL on the proxied hostnames.
- WKD: static files under `openpgpkey.abu.rocks/.well-known/openpgpkey/{policy,hu/<hash>}`,
  served `application/octet-stream`, with the CORS header WKD wants.
- PGP key generated with the flag in the UID comment; export the binary pubkey to the hu/ path.

## Ethics / robustness
- All on our own domains (consenting org) = GREEN. Personas (ClearPane, Halcyon Strategies,
  curator) are fictional; no real third party, no real creds, no private individual.
- Snapshot fallback: if crt.sh indexing lags, host a small crt.sh-style CT-JSON endpoint so hop 1
  never depends on external timing.
- Static sites only (no scanning replica), egress not needed. Brief says "passive recon only" via
  the site content/rules; players touch only the one h7tex.com host (via pointer), never enumerate it.

## Build order
1. DNS (Abu adds all 4 records himself) -> propagate. [BLOCKS rest]
2. Build site content + favicon + analytics snippet + PGP key + WKD files (local, repo-side).
3. Deploy to atom (nginx vhosts + tunnel ingress).
4. Verify: crt.sh shows the abu.rocks hosts; synthetic solver walks crt.sh -> favicon -> pointer ->
   WKD -> flag.
