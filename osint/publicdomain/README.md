# Public Domain

**Category:** osint  **Difficulty:** hard  **Author:** abu

> Some operators still think their domains are private. Infrastructure has a longer memory than they do.

Hosted as static sites (`challenge/sites/`, nginx config in `challenge/deploy/`). ClearPane, Halcyon Strategies and the curator are made-up personas on my own domains.

## Solution

The description doesn't name anything, so the only lead is the author. Abu means `abu.rocks`.

The cert on the site is a Cloudflare wildcard, so it gives nothing away, but Certificate Transparency does. Searching crt.sh (or certspotter) for `abu.rocks` shows two hosts that aren't linked from anywhere: `clearpane.abu.rocks`, an "independent" leak site, and `cdn-static-3.abu.rocks`, where ClearPane loads its CSS and JS from.

The stylesheet at `https://cdn-static-3.abu.rocks/site.css` has a build comment listing every site it serves. One of them is `halcyon-strategies.h7tex.com`, a reputation management firm that has nothing to do with ClearPane on paper.

To confirm it's the same operator:

- the favicon is byte-identical on all three hosts (Shodan mmh3 `630558264`)
- ClearPane and Halcyon embed the same analytics id, `PA-9F3C71E8`

Halcyon's `/.well-known/security.txt` gives a PGP contact, `curator@abu.rocks`. An abu.rocks address on an h7tex.com site, so that's the link back.

The key is published over WKD, so fetch it by address:

```sh
gpg --locate-external-keys curator@abu.rocks
```

It comes from `openpgpkey.abu.rocks`, and the flag is in the UID comment. `solution/solve.py` walks the same chain (use a browser User-Agent, Cloudflare blocks bare bot ones; if crt.sh is down any CT search works).

Flag: `H7CTF{4fb846630ae38a205b}`
