# Gone Not Forgotten

**Category:** forensics  **Difficulty:** medium  **Author:** abu

> A phone lands on the evidence bench for a harassment case, and the suspect is adamant they never sent anything ugly. Nova Messenger agrees with them: nothing there.
>
> Deleting a thing and being rid of it were never the same move.

Handout: `handout/evidence.zip` (`messages.db` and `secure.xml`, pulled with adb as root from an Android 14 emulator).

## Solution

First we just queried the live table:

```
sqlite3 messages.db "SELECT _id, thread, sender, body FROM messages;"
```

Normal chatter, except the `ops` thread has a gap in the `_id` sequence and a message from `mallory` saying "burn this after you read it". The thing it refers to is gone.

An in-app delete is just a SQL `DELETE`. With `secure_delete` off, SQLite marks the cell free and leaves the bytes alone. FQLite, `undark`, `sqlite3 messages.db .recover` or a manual freelist carve all bring the row back. The body isn't text though, it's a hex string.

`secure.xml` is the app's shared prefs, and it explains itself:

```
stored_body_encoding = hex(xor(body, obfuscation_key))
obfuscation_key      = n0v4ch4t
```

Hex-decode the recovered body, XOR with `n0v4ch4t`, and the deleted message is the flag. `strings messages.db | grep H7CTF` finds nothing, because every body is stored this way.

```
python3 solution/solve.py messages.db secure.xml
```

Flag: `H7CTF{7adf9695fb655c752810}`
