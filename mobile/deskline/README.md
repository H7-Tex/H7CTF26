# Help Yourself

**Category:** mobile  **Difficulty:** medium  **Author:** abu

> Deskline runs the support desk our agents live in all day, one ticket queue that never stops refilling. Tucked in among the customer complaints is a single note marked agent-only, and the desk is quite sure you'll never reach it.
>
> So help yourself.

Handout: `handout/deskline-1.6.0.apk.zip`. Per-team Flask sync backend (`backend/`) on port 8080. The APK is built from `app/` with `app/build.sh` (aapt2, javac, d8, apksigner, no Gradle).

## Solution

Install the APK, put your instance URL in the Server field and tap "Sync my queue". The app pulls the ticket queue into a local SQLite DB. It also files one agent-only note into a separate `credentials` table that the UI never shows. That note is the flag.

The manifest exports `TicketProvider` (authority `com.deskline.tickets`) with no permission. In jadx, `TicketProvider.query()` looks like this:

```java
String sql = "SELECT id, subject, body FROM tickets";
if (selection != null && selection.trim().length() > 0)
    sql += " WHERE " + selection;
return db.rawQuery(sql, null);
```

The caller's selection goes straight into the query. Plain content provider SQL injection. The provider returns three columns, so UNION the hidden table in with three:

```
adb shell 'content query --uri content://com.deskline.tickets/tickets --where "1=1 UNION SELECT id,label,value FROM credentials"'
```

Quote the whole device command, otherwise the selection gets split before the `content` tool sees it. The `vault-unseal-code` row has the flag in its `body` column. `solution/solve.sh` does exactly this.

The flag is dynamic and only lands in your device DB after a sync; the APK never contains it.
