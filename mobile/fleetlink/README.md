# FleetLink (mobile)

Android fleet/driver app + signed REST API. Hard. Every request is HMAC-signed; the key and
canonicalization are compiled into the app. Reverse `Signer` (secret + `SHA256(secret:deviceId)`
key derivation + `METHOD\nPATH\nSORTED_QUERY\nTS` canonical string), then forge a call the
app never makes (`scope=all`) to read the dispatcher-only manifest (the flag). A captured
signature cannot be replayed for a different request, so the RE is required.

## Layout

```
app/          Android sources + manual build (no Gradle)
  src/com/fleetlink/{MainActivity,Session,ApiClient,Signer}.java
  build.sh    aapt2 + javac(temurin-17) + d8 + zipalign + apksigner
backend/      per-team Flask signed API (Dockerfile, requirements.txt, app.py)
handout/      fleetlink-4.1.0.apk
solution/     solve.py
writeup/      writeup.md
challenge.yml
```

## Build

```
cd app && ./build.sh          # -> ../handout/fleetlink-4.1.0.apk
```

## Backend

`FLAG` is injected by Anvil (single dynamic flag). `FLEET_APP_SECRET` has a safe default
(matches the value compiled into the APK; override only if you rebuild the APK to match).
Local run:

```
cd backend && FLAG='H7CTF{...}' python3 app.py
```

## Validation

Verified end to end on an Android 14 emulator + backend: the app's signed
`GET /api/v1/trips?scope=mine` is accepted (200), and `solution/solve.py` (a Python
reimplementation of `Signer`) forges `GET /api/v1/fleet/manifest?scope=all` to the flag.
`scope=mine` returns the 403 hint naming the required scope (zero-guess). No `H7CTF` string
is present in the APK.

## Deploy notes (Anvil, later)

HTTP ingress on 8080 (`instancing: on_demand`), image `h7ctf26/fleetlink`, APK handout
attached. Per-team: Anvil injects `FLAG`; players point the Server field at their instance.
The APP_SECRET is baked into the shipped APK, so keep the default (or rebuild the APK if you
change it).
