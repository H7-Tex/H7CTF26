# Onyx Locker

**Category:** mobile  **Difficulty:** easy  **Author:** abu

> Onyx Locker keeps all your secrets on the phone, never in the cloud, exactly as promised. The vault's recovery code sits right there on the device, sealed up tight and yours alone.
>
> Yours, and anyone who bothers to look.

Handout: `handout/onyx-locker-2.4.0.apk.zip`. Per-team Flask sync backend (`backend/`) on port 8080.

## Solution

Install the APK, set the Server field to your instance and tap "Unlock and sync vault". The app pulls the vault and caches it on the device. The "Onyx account recovery code" in that vault is the flag.

First thing in the manifest: `android:debuggable="true"`. That means `run-as` works, and we can read the app's private files over adb:

```
adb exec-out run-as com.onyx.locker cat files/vault.enc > vault.enc
```

It's encrypted, so open `com/onyx/locker/VaultCrypto` in jadx:

```java
private static final byte[] KEY = "0nyxL0ck3r_v4ult_K3y_32bytes_ok!".getBytes();
private static final byte[] IV  = "0nyxLckrIV_16byt".getBytes();
// AES/CBC/PKCS5Padding
```

Hardcoded key and IV. Decrypt it:

```
KEYHEX=$(printf '0nyxL0ck3r_v4ult_K3y_32bytes_ok!' | xxd -p | tr -d '\n')
IVHEX=$(printf '0nyxLckrIV_16byt' | xxd -p | tr -d '\n')
openssl enc -d -aes-256-cbc -K "$KEYHEX" -iv "$IVHEX" -in vault.enc
```

Out comes the vault JSON with the recovery code. `solution/solve.sh` does both steps. Proxying the app's traffic to `/api/v1/vault/sync` also shows the vault, which is fine too.

The flag is dynamic, one per team, and never in the APK.
