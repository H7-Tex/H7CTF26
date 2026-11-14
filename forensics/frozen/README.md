# Frozen Assets

**Category:** forensics  **Difficulty:** insane  **Author:** abu

> DESKTOP-M-HALE keeps the finance team's books, and overnight every file on its E: drive turned to expensive noise. Security pulled a full image of the box while it was still warm.
>
> Whatever froze the assets left a copy of itself behind. Rude of it, and useful to you.

Handout: `challenge/IR-DESKTOP-M-HALE.zip` (Avast artifacts plus the seven encrypted E: files).

This is a rebuild of an older challenge of mine that I lost. The Avast chest is a replica of the real format (same paths, same XOR-key scheme, same vault/crossRef/stream schema), not a capture from a real Avast install. To rebuild the handout:

```
x86_64-w64-mingw32-gcc challenge/sample_src/sample.c -o challenge/ProtonVPN_x64final.exe -ladvapi32
FLAG=... python3 challenge/gen_efiles.py
python3 challenge/build_chest.py
# then zip chest_root + E_encrypted into IR-DESKTOP-M-HALE.zip
```

## Solution

The E: files can't be decrypted without reversing the malware, and the malware is only available from inside the Avast quarantine. So it's three stages in order.

**Avast Virus Chest.** The zip has `ProgramData\Avast Software\Avast\chest\$AV_ASW\$VAULT\vault.db` and `Program Files\Avast Software\Avast\aswntsqlite.dll`. `vault.db` is a SQLite file XOR'd with a 16384-byte key that lives in the DLL. maldump knows the stock key, but this build uses a custom one, so you have to lift it yourself. XOR the first 16 bytes of `vault.db` with `SQLite format 3\x00` to get the key prefix, find that prefix in the DLL, and read 16 KB from there. XOR the whole vault with it (`i % 16384`) and it opens as a normal database. There's a decoy item, so pick the right one:

```sql
SELECT data FROM vault
JOIN crossRef ON id = crossRef.vaultid
JOIN stream ON crossRef.streamId = stream.streamId
WHERE filename LIKE '%ProtonVPN%';
```

That blob is `ProtonVPN_x64final.exe`.

**Reversing the sample.** It imports `CryptAcquireContext`, `CryptCreateHash`, `CryptDeriveKey` and `CryptEncrypt`. It hashes an empty password with `CALG_MD5`, then calls `CryptDeriveKey(CALG_AES_128, hHash)`, CBC, zero IV. When the key length is not longer than the hash, CryptDeriveKey just uses the hash bytes, so the key is `MD5("") = d41d8cd98f00b204e9800998ecf8427e`.

**Decrypting E:.** AES-128-CBC, that key, 16 zero bytes as IV, strip PKCS7. The flag is in `recovery_codes.txt`.

```
python3 solution/solve.py <extracted_zip_dir> <extracted_zip_dir>/E
```

Flag: `H7CTF{750b6f18160c332f9f2b}`
