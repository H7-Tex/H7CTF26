# Deleted, Not Gone

`forensics` / `medium` / static handout (real Android app DB + prefs), static flag.

Mobile/app forensics. A chat app's SQLite database and its shared-preferences were pulled
from a seized Android device. One incriminating message was deleted in-app; the row is gone
from the live table but its bytes remain in the SQLite freelist. The app stores message
bodies obfuscated (`hex(xor(body, key))`) and leaks the key in its own prefs. The player
recovers the deleted record and de-obfuscates it with the key to read the message (the
flag).

## Realism
Genuinely captured: a real Android 14 emulator (Golem), a real on-device SQLite DB created
by `sqlite3` at a real app-data path, populated and then deleted with `secure_delete=OFF`
(so the record is recoverable), and the DB + `secure.xml` pulled with `adb` as root. Opens
in FQLite / undark / sqlite3 like any acquired app database.

## Files
- `challenge.yml` : definition (static flag; two small attachment handouts).
- `solution/solve.py` : reference solver (carve the deleted freelist record + hex/XOR de-obfuscate).
- `solution/README.md` : full intended path.
- `writeup/README.md` : full explanation.
- `handout/messages.db` (12 KB) + `handout/secure.xml` (255 B) : the pulled artifacts.

## Solve (spoiler)
Live query shows a deleted `_id` in the `ops` thread. Recover the deleted row from the
freelist (FQLite / `sqlite3 .recover` / carve) -> a hex body. `secure.xml` gives the recipe
`hex(xor(body, obfuscation_key))` and the key `n0v4ch4t`. Hex-decode + XOR -> the flag.
Validated end-to-end on the pulled artifacts; the flag is not plaintext in the DB.

## Flag model
Tiny real static artifacts -> Anvil attachments + static flag (anti-share = the recovery
effort + score decay). Could be made per-team dynamic (regenerate the DB with a per-team
flag on the emulator) if wanted.

## Fairness / anti-agent notes
- Not `strings`-recoverable: the body is stored `hex(xor(...))` and the row is deleted, so
  neither a query nor a grep yields the flag.
- Two-artifact reasoning (the deleted DB record + the prefs key), the divergence principle.
- Real skill: SQLite deleted-record carving (freelist) + reversing app-level obfuscation -
  standard mobile app-forensics, and a real lesson (in-app "delete" leaves the bytes, and
  apps that keep their obfuscation key next to the data are trivially reversible).
- Real basis: seized-device chat-app forensics; recoverable SQLite deletes are a staple of
  mobile investigations (WhatsApp/Signal/etc. lean on WAL + freelist remnants).
