# Public Domain — reference solution

Infrastructure-attribution OSINT. The only nudge is the challenge itself (author: **Abu**) and the
one-line brief hinting at *domains*. Everything is on our own infrastructure (abu.rocks + h7tex.com).

## Chain
1. **Author → domain.** The author is Abu; his personal domain is `abu.rocks`.
2. **Certificate Transparency.** Enumerate CT for `abu.rocks` (crt.sh / certspotter / censys). Among
   the certs, two non-obvious hosts appear: `clearpane.abu.rocks` (a self-described "independent"
   leak site) and `cdn-static-3.abu.rocks` (its asset host). ClearPane's page also loads its CSS/JS
   from `cdn-static-3`, so page source reaches the same place.
3. **Shared asset → the leak.** `https://cdn-static-3.abu.rocks/site.css` is a shared theme; its
   header comment lists the sites it serves — including `halcyon-strategies.h7tex.com`, a corporate
   reputation-management firm that publicly has nothing to do with ClearPane.
4. **Fingerprint confirmation.** The custom favicon is byte-identical across ClearPane, the CDN host,
   and Halcyon (Shodan-style MurmurHash3 = `630558264`), and both fronts embed the same self-hosted
   analytics account `PA-9F3C71E8`. Same operator, two faces.
5. **Operator identity.** `https://halcyon-strategies.h7tex.com/.well-known/security.txt` names the
   PGP contact `curator@abu.rocks` (an abu.rocks identity on an h7tex.com site — the tell) plus the
   key fingerprint.
6. **WKD → flag.** Fetch the key by address via Web Key Directory:
   `gpg --locate-external-keys curator@abu.rocks` (served from `openpgpkey.abu.rocks`). The key's
   UID comment is the flag.

`H7CTF{4fb846630ae38a205b}`

## Run
```
python3 solve.py
```
(Use a browser/curl User-Agent — Cloudflare blocks bare bot UAs. crt.sh is occasionally down; any
CT source works since the names are logged in CT.)
