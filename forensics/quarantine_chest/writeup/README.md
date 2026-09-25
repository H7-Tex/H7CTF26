# Cold Vault - writeup

Three gated stages; you cannot skip to the E: files (their AES key is only knowable by
reversing the sample, which is only recoverable from the Avast chest).

## Stage 1 - reverse the Avast Virus Chest
The handout has real Avast paths: `ProgramData\Avast Software\Avast\chest\` (with `index.xml`
and `$AV_ASW\$VAULT\vault.db`) and `Program Files\Avast Software\Avast\aswntsqlite.dll`.
`vault.db` is a SQLite database whole-file XOR'd with a 16384-byte key that lives in
`aswntsqlite.dll` (the documented Avast quarantine format; cf. reversingfun "Reversing Avast
Quarantine" + NUKIB/maldump). The maldump tool won't help here - this build uses a *custom*
key, so you must lift it from the DLL:
1. Recover the key prefix: `key[:16] = vault.db[:16] XOR "SQLite format 3\x00"`.
2. Find that prefix in `aswntsqlite.dll` and read the full 16 KB from there.
3. XOR `vault.db` with the key (index `i % 16384`) -> a clean SQLite DB.
4. Carve the sample: `SELECT data FROM vault JOIN crossRef ON id=crossRef.vaultid JOIN stream
   ON crossRef.streamId=stream.streamId WHERE filename LIKE '%ProtonVPN%'` (there's a decoy
   quarantined item too). The blob is `ProtonVPN_x64final.exe`.

## Stage 2 - RE the recovered sample
The PE imports `CryptAcquireContext / CryptCreateHash / CryptDeriveKey / CryptEncrypt`
(advapi32). The routine: `CryptCreateHash(CALG_MD5)` over an EMPTY password, then
`CryptDeriveKey(CALG_AES_128, hHash)`, CBC mode, zero IV. CryptDeriveKey with a key length
<= the hash length uses the hash bytes directly, so **the AES-128 key = MD5("") =
`d41d8cd98f00b204e9800998ecf8427e`**, IV = 16 zero bytes, PKCS7 padding.

## Stage 3 - recover the E: files
Decrypt each `E\*.enc` with AES-128-CBC, key `MD5("")`, zero IV, strip PKCS7. The flag is in
`recovery_codes.txt`. See `solution/solve.py` (walks all three stages).

## Build
`x86_64-w64-mingw32-gcc challenge/sample_src/sample.c -o challenge/ProtonVPN_x64final.exe
-ladvapi32` -> `FLAG=... python challenge/gen_efiles.py` -> `python challenge/build_chest.py`
-> zip `chest_root` + `E_encrypted` into `IR-DESKTOP-M-HALE.zip`.

## Realism note
The chest is a faithful *replica* of the Avast format (right paths, right XOR-key mechanism,
right vault/crossRef/stream schema). For byte-perfect authenticity a one-time capture on a
real Windows VM with Avast installed (quarantine a benign sample) is the gold-standard upgrade
- the recovery technique is identical either way.
