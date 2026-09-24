# Deskline (mobile)

Android support-agent app + per-team sync backend. Medium. An exported `ContentProvider`
builds its query by concatenating the caller's selection (`"...WHERE " + selection`) - a
classic content-provider SQL injection. UNION-select the hidden `credentials` table to
recover the agent-only note (the flag).

## Layout

```
app/          Android sources + manual build (no Gradle)
  src/com/deskline/{MainActivity,Session,ApiClient,DeskDb,TicketProvider}.java
  build.sh    aapt2 + javac(temurin-17) + d8 + zipalign + apksigner
backend/      per-team Flask sync API (Dockerfile, requirements.txt, app.py)
handout/      deskline-1.6.0.apk
solution/     solve.sh
writeup/      writeup.md
challenge.yml
```

## Build

```
cd app && ./build.sh          # -> ../handout/deskline-1.6.0.apk
```

## Backend

`FLAG` is injected by Anvil (single dynamic flag). Local run:

```
cd backend && FLAG='H7CTF{...}' python3 app.py
```

## Validation

Verified end to end on an Android 14 emulator: the app silent-auths and syncs the queue
into SQLite (public `tickets` + hidden `credentials` row), and
`content query --uri content://com.deskline.tickets/tickets --where "1=1 UNION SELECT
id,label,value FROM credentials"` dumps the flag. Baseline query returns only public
tickets. No `H7CTF` string is present in the APK.

## Deploy notes (Anvil, later)

HTTP ingress on 8080 (`instancing: on_demand`), image `h7ctf26/deskline`, APK handout
attached. Per-team: Anvil injects `FLAG`; players point the Server field at their instance.
