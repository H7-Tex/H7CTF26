# Deleted, Not Gone: writeup

## The setup
Data pulled from a seized Android phone's chat app (Nova Messenger): its SQLite database
(`messages.db`) and its shared-preferences (`secure.xml`). The suspect deleted one message
in-app and claims it never existed. In-app "delete" is a SQL `DELETE`, which removes the
row from the table but not the bytes from the file - so the record is recoverable.

## Why `strings` / a query fails
Two layers stop the shortcuts: the row is deleted (so a normal `SELECT` never shows it),
and the app stores every body as `hex(xor(plaintext, key))` (so `strings messages.db | grep
H7CTF` finds nothing even in the freed bytes). You must recover the deleted record and undo
the obfuscation.

## Solve
1. **Spot the deletion.** `SELECT _id,thread,sender,body FROM messages` shows a gap in the
   `_id` sequence in the `ops` thread and a dangling "burn this after you read it" - a
   message was deleted.
2. **Recover the row.** `secure_delete` is off, so the deleted cell survives in a freed
   page. FQLite, `undark`, `sqlite3 messages.db .recover`, or a freelist carve pulls it
   back as a hex string body.
3. **De-obfuscate.** `secure.xml` documents `stored_body_encoding =
   hex(xor(body, obfuscation_key))` and leaks `obfuscation_key = n0v4ch4t`. Hex-decode the
   recovered body, XOR with the key -> the plaintext, which is the flag.

## Notes
- Genuinely captured off a real Android 14 emulator (real on-device SQLite DB + prefs,
  pulled via adb root); opens in the standard mobile-forensics tools.
- Anti-agent: recovering a deleted SQLite record and reversing app obfuscation across two
  artifacts is real app-forensics reconstruction, not a grep.
- Real basis: apps' "delete" leaves recoverable rows, and storing an obfuscation key beside
  the data it "protects" is a real, common weakness.
