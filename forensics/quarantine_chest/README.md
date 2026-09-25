# Cold Vault (forensics) — the quarantine chain

Three-stage DFIR (rebuild + upgrade of Abu's lost original): reverse the Avast Virus Chest to
recover a quarantined sample, RE its CryptoAPI crypto, decrypt the 7 encrypted E: files.

- `challenge/sample_src/sample.c` — the "recovered sample" (real Windows PE, CryptoAPI:
  MD5("")→CryptDeriveKey AES-128, CBC/zero-IV/PKCS7). Build: `x86_64-w64-mingw32-gcc
  sample_src/sample.c -o ProtonVPN_x64final.exe -ladvapi32`.
- `challenge/gen_efiles.py` — the 7 encrypted E: files (flag in recovery_codes.txt).
- `challenge/build_chest.py` — assembles the Avast chest replica (XOR'd vault.db with the
  vault/crossRef/stream schema + aswntsqlite.dll carrying a custom 16 KB key + index.xml).
- `challenge/IR-DESKTOP-M-HALE.zip` — the handout (triage bundle: Avast artifacts + E: files).
- `solution/solve.py` — full 3-stage reference solve. `writeup/README.md` — explanation.

Static-artifact handout + static flag. Validated end-to-end: full solve recovers
H7CTF{...} from the packaged handout; flag not strings-greppable. Avast format is a faithful
replica (real paths + XOR-key mechanism + schema); a real-Windows-VM capture is the optional
byte-fidelity upgrade. Rebuild the whole handout: run the three build steps above, then zip
chest_root + E_encrypted into IR-DESKTOP-M-HALE.zip.
