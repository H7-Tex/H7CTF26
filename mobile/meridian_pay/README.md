# Meridian Pay (mobile)

Android neobank client plus a per-team staging API. Four gated dynamic flags across four
client and API bug classes: exported deep-link redirection into an authenticated WebView
(v1), exported content-provider path traversal (v2), broken object-level authorization
(v3), and mass-assignment privilege escalation (v4).

## Layout

```
app/          Android sources + manual build pipeline (no Gradle)
  AndroidManifest.xml
  src/com/meridian/pay/*.java
  res/...
  build.sh    aapt2 + javac(temurin-17) + d8 + zipalign + apksigner
backend/      per-team Flask API (Dockerfile, requirements.txt, app.py)
handout/      meridian-pay-3.2.1.apk   (player handout)
solution/     solve.sh reference walkthrough
writeup/      writeup.md
challenge.yml
```

## Building the APK

```
cd app && ./build.sh          # writes ../handout/meridian-pay-3.2.1.apk
```

Needs the Android SDK (build-tools 35, platform android-35) and a JDK 17 for `javac`
(`~/.local/share/mise/installs/java/temurin-17`). Produces a debug-signed APK. No Gradle,
no dependency downloads.

## Backend

`FLAG_V1..FLAG_V4` are injected by Anvil (dynamic flags). `MP_JWT_SECRET` and
`MP_CLIENT_TOKEN` have safe defaults; override in prod if desired. Single gunicorn worker
is required (v4 mutates in-memory role state).

Local run:

```
cd backend && FLAG_V1=... FLAG_V2=... FLAG_V3=... FLAG_V4=... python3 app.py
```

## Deploy notes (Anvil, later)

- HTTP ingress on 8080 (`instancing: on_demand`), image `h7ctf26/meridian-pay`.
- APK handout attached (16 KB, well under the attachment cap).
- Per-team: Anvil injects `FLAG_V1..V4`; players point the app's Server field at their
  instance URL (staging build behaviour).

## Validation

Built and validated end to end on an Android 14 emulator against the live backend:
silent device auth, v1 deep-link renders the flag in the WebView, v2 provider traversal
leaks `session.xml`, and the stolen JWT drives v3 (BOLA on account 1002) and v4
(mass-assign to admin ledger). No `H7CTF` string is present in the APK.
