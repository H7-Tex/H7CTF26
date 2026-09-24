# Onyx Locker (mobile)

Android password manager + per-team sync server. On-ramp difficulty. Two at-rest failures:
the shipped build is **debuggable** (`run-as` reads private storage), and the cached vault
is AES-256-CBC with a **hardcoded key + IV**. Recover the vault recovery code (the flag).

## Layout

```
app/          Android sources + manual build (no Gradle)
  src/com/onyx/locker/{MainActivity,Session,ApiClient,VaultCrypto}.java
  build.sh    aapt2 + javac(temurin-17) + d8 + zipalign + apksigner
backend/      per-team Flask sync API (Dockerfile, requirements.txt, app.py)
handout/      onyx-locker-2.4.0.apk
solution/     solve.sh
writeup/      writeup.md
challenge.yml
```

## Build

```
cd app && ./build.sh          # -> ../handout/onyx-locker-2.4.0.apk
```

## Backend

`FLAG` is injected by Anvil (single dynamic flag). Local run:

```
cd backend && FLAG='H7CTF{...}' python3 app.py
```

## Validation

Verified end to end on an Android 14 emulator: the app silent-auths and syncs, writes the
AES-encrypted vault to internal storage, `adb exec-out run-as com.onyx.locker cat
files/vault.enc` extracts it (debuggable), and openssl with the APK-recovered key/IV
decrypts it to the flag. No `H7CTF` string is present in the APK.

## Deploy notes (Anvil, later)

HTTP ingress on 8080 (`instancing: on_demand`), image `h7ctf26/onyx-locker`, APK handout
attached. Per-team: Anvil injects `FLAG`; players point the Server field at their instance.
