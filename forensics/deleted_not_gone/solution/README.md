# Deleted, Not Gone: intended solution

```
unzip evidence.zip        # -> messages.db + secure.xml
python3 solve.py messages.db secure.xml
```

## Path
1. **Look at the live data first.** `sqlite3 messages.db "SELECT * FROM messages;"` shows
   normal chatter and, in the `ops` thread, one message from `mallory` that says "burn this
   after you read it" - but the message it refers to is gone (a missing `_id`). Something
   was deleted.
2. **Recover the deleted row.** SQLite does not zero a deleted row's bytes (this DB has
   `secure_delete` off), so the record still sits in a freed page. Pull it with FQLite,
   `undark`, or `sqlite3 messages.db .recover` (or scan the freelist). The recovered body
   is not readable text - it's a hex string.
3. **De-obfuscate.** `secure.xml` tells you exactly how the app stores bodies:
   `stored_body_encoding = hex(xor(body, obfuscation_key))`, and it leaks the
   `obfuscation_key` itself (`n0v4ch4t`). Hex-decode the recovered body and XOR it with the
   key -> the plaintext message, which is the flag.

## Why a grep fails
The stored body is `hex(xor(plaintext, key))`, so `strings messages.db | grep H7CTF`
finds nothing. And the row is deleted, so it isn't in a normal query either. You have to
recover the deleted record *and* reverse the app's obfuscation using the key from the
second artifact.
