# Public Domain

**Category:** osint · **Difficulty:** hard · **Author:** Abu

## Premise
Real infrastructure-attribution OSINT, the way Bellingcat links "unconnected" operations: two web
fronts that present as strangers are secretly run by one operator, and only their shared
infrastructure gives them away. Everything lives on our own consenting domains (abu.rocks +
h7tex.com); no real third party, no private individual, passive recon only.

The brief gives nothing away — one line, a pun on *domain*, and the author's name (Abu). That name
is the entire on-ramp: players already know Abu runs this event, so they start from him, reach his
personal domain, and let the infrastructure do the rest.

## Walkthrough
- **Author → abu.rocks.** Investigating the author lands on `abu.rocks`.
- **Certificate Transparency.** Cloudflare fronts abu.rocks with a wildcard cert, so the dashboard
  won't hand you subdomains — but CT will. crt.sh / certspotter for `abu.rocks` surfaces two hosts
  that don't advertise themselves: `clearpane.abu.rocks` (an "independent, no-patron" transparency
  site) and `cdn-static-3.abu.rocks` (its static-asset host). ClearPane loads its stylesheet from
  the CDN host, so the pivot is doubly reachable.
- **The leak.** The shared stylesheet `cdn-static-3.abu.rocks/site.css` carries an internal build
  comment listing the properties it serves — and ClearPane's "independent" CDN also serves
  `halcyon-strategies.h7tex.com`, a corporate reputation-management (astroturf) firm.
- **Corroboration (fingerprints).** The favicon is byte-identical on all three hosts
  (Shodan MurmurHash3 `630558264`); ClearPane and Halcyon both embed the same self-hosted analytics
  account `PA-9F3C71E8`. Shared CDN + shared favicon + shared analytics = one operator behind two
  faces. (These are the real attribution primitives: favicon hashing, reused analytics IDs, cert
  transparency.)
- **The operator.** Halcyon's `/.well-known/security.txt` lists the PGP contact `curator@abu.rocks`
  — an abu.rocks address on an h7tex.com site, tying the "respectable" firm straight back to the
  leak-site domain — plus the key fingerprint `6D43...0AF6`.
- **WKD → flag.** The key is published via Web Key Directory. Fetch it by address:
  `gpg --locate-external-keys curator@abu.rocks` (served from `openpgpkey.abu.rocks`). The flag is
  the UID comment: `H7CTF{4fb846630ae38a205b}`.

## Why it's fair, not guessy
Every hop is a deterministic, signposted artifact — a CT record, a served file, a favicon hash, a
security.txt, a WKD key — not a hunch. The flag exists only inside the WKD-served key; you cannot
reach it without doing the attribution. The nudge points at *domains* (infrastructure), deliberately
steering players onto the solvable chain and away from doxxing rabbit holes.

## Operational notes
- Hosted on atom behind the existing cloudflared tunnel; TLS via Cloudflare Universal SSL. A named
  Let's Encrypt cert for clearpane + cdn-static-3 is issued purely so their names appear in CT
  (Cloudflare's wildcard would otherwise hide them). See `challenge/deploy/` and `DEPLOY.md`.
- crt.sh is intermittently down; the names are in CT regardless, so any CT source resolves hop 1.
- Cloudflare may 403 bare bot User-Agents; standard tooling (browser, curl, gpg, CT search) works.
