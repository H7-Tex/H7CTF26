# Paper Trail - writeup

An OSINT on-ramp built as a self-contained metadata golden thread. No live internet is required (so
it can never break or go stale), but it exercises real OSINT muscle: pivot on an identifier, pick the
right source out of several, and read metadata other people forget is there. It's a controlled,
bundled footprint - the deterministic cousin of a live-footprint OSINT.

## The thread
1. **statement.pdf** - PDF document metadata carries `Author: Mara Chen` and, in `Keywords`, the
   pivot `handle:mchen_prints`. (People routinely leak handles/usernames/real names in Office/PDF
   metadata.)
2. **exports/mchen_prints.json** - three persona exports are in the bundle; only this one matches the
   handle. Its pinned post says the "recovery code" is in the metadata of `gallery/final_print.jpg`.
3. **gallery/final_print.jpg** - the flag is in the EXIF `ImageDescription`; the GPS tag
   (19.033 N, 72.826 E, Mahalaxmi Mumbai) is a redundant confirming clue.

## Why the decoys matter
Two other gallery photos carry **fake** `H7CTF{...}` strings in their EXIF, so `exiftool gallery/* |
grep H7CTF` yields three candidates. The challenge is deciding *which* - which is exactly what the
thread does: the pinned post names `final_print.jpg`. This is the small but real OSINT lesson -
corroborate, don't grab the first hit.

## Realism note / upgrade path
Bundled footprint keeps it deterministic and dependency-free (good for a weekly). The natural
"harder + more real" upgrade is a **hosted controlled footprint**: stand the persona up on our own
domains (a printshop.social-style profile page, a paste, an image host) so players pivot across live
services we control. Same golden-thread design; just hosted. Logged as a future infra option.

## Build
`python3 challenge/gen.py` writes `challenge/leak_bundle/` (statement.pdf with stamped metadata, 3
JSON exports, 4 JPEGs with crafted EXIF incl. the flag + decoys). Zip `leak_bundle/` into
`paper-trail.zip`.

## Teaching
Document/PDF metadata (`Author`, `Keywords`, `Producer`), image EXIF (`ImageDescription`,
`UserComment`, GPS), identifier pivoting, and source disambiguation - the everyday primitives of
metadata-driven OSINT.
