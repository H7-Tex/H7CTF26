# Onyx Locker - writeup

Onyx Locker is an Android password manager (v2.4.0) plus a per-team sync server. Install
it, point the Server field at your instance, and tap "Unlock and sync vault". The app
silently authenticates the device, pulls the vault, and caches it locally. The vault's
"account recovery code" is the flag, minted per team by the backend, and never present in
the APK.

Two rungs, both classic mobile at-rest failures.

## Rung 1 - the build is debuggable

`AndroidManifest.xml` ships with `android:debuggable="true"`. Shipping a production build
debuggable means anyone with adb can run *as* the app and read its private storage:

```
adb exec-out run-as com.onyx.locker cat files/vault.enc > vault.enc
```

`files/vault.enc` is the cached vault. It is not plaintext, though.

## Rung 2 - the vault key is compiled into the app

Decompile the APK (`jadx onyx-locker-2.4.0.apk`) and read `com/onyx/locker/VaultCrypto`:

```java
private static final byte[] KEY = "0nyxL0ck3r_v4ult_K3y_32bytes_ok!".getBytes();
private static final byte[] IV  = "0nyxLckrIV_16byt".getBytes();
// Cipher.getInstance("AES/CBC/PKCS5Padding")
```

AES-256-CBC with a hardcoded key and a fixed IV. Decrypt the cached blob with the key you
just recovered:

```
KEYHEX=$(printf '0nyxL0ck3r_v4ult_K3y_32bytes_ok!' | xxd -p | tr -d '\n')
IVHEX=$(printf '0nyxLckrIV_16byt' | xxd -p | tr -d '\n')
openssl enc -d -aes-256-cbc -K "$KEYHEX" -iv "$IVHEX" -in vault.enc
```

The decrypted JSON is the vault; the "Onyx account recovery code" item is the flag.

## Notes

- The flag is minted per team by the backend and only ever exists inside the decrypted
  vault on the team's own device. The APK contains the key and the bug, never a flag.
- Alternate path: intercepting the app's TLS/cleartext traffic to `/api/v1/vault/sync`
  also reveals the vault; the intended, no-proxy path is the debuggable + at-rest crypto
  failure above.
