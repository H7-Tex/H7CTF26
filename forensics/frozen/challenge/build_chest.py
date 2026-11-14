#!/usr/bin/env python3
# Assemble the Avast Virus Chest replica (per the maldump/reversingfun format):
#   - vault.db : SQLite with vault/crossRef/stream tables holding the quarantined sample
#     stream, whole-file XOR'd with a 16384-byte key (index = i % 16384).
#   - aswntsqlite.dll : carries that 16 KB key in .rodata (custom key, so the maldump tool
#     with its baked-in real key FAILS -> players must reverse the DLL for the key: XOR the
#     encrypted vault.db header against the SQLite magic to get the key prefix, find it in
#     the DLL, lift the full 16 KB).
#   - index.xml : ChestEntry with <IDPBlob> (its presence routes the item to vault.db).
import os, sqlite3, subprocess, struct, secrets

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "ProtonVPN_x64final.exe")
OUT = os.path.join(HERE, "chest_root")
VAULTDIR = os.path.join(OUT, "ProgramData", "Avast Software", "Avast", "chest", "$AV_ASW", "$VAULT")
os.makedirs(VAULTDIR, exist_ok=True)

def xor(data, key):
    b = bytearray(data)
    for i in range(len(b)):
        b[i] ^= key[i % len(key)]
    return bytes(b)

# 1. build a clean SQLite vault.db
clear = os.path.join(HERE, "_vault_clear.db")
if os.path.exists(clear):
    os.remove(clear)
db = sqlite3.connect(clear)
db.executescript("""
CREATE TABLE vault (id INTEGER PRIMARY KEY, filename TEXT, virus TEXT, size INTEGER, added INTEGER);
CREATE TABLE crossRef (vaultid INTEGER, streamId INTEGER);
CREATE TABLE stream (streamId INTEGER PRIMARY KEY, data BLOB);
""")
sample = open(SAMPLE, "rb").read()
# a decoy quarantined item (realism) + the real one
db.execute("INSERT INTO vault VALUES (1,'C:\\\\Users\\\\m.hale\\\\Downloads\\\\setup_helper.tmp','Win32:Evo-gen',34210,1758300000)")
db.execute("INSERT INTO stream VALUES (1,?)", (secrets.token_bytes(34210),))
db.execute("INSERT INTO crossRef VALUES (1,1)")
db.execute("INSERT INTO vault VALUES (2,'C:\\\\Users\\\\m.hale\\\\Downloads\\\\ProtonVPN_x64final.exe',?,?,1758470000)",
           ("Win32:RansomX-gen [Ransom]", len(sample)))
db.execute("INSERT INTO stream VALUES (2,?)", (sample,))
db.execute("INSERT INTO crossRef VALUES (2,2)")
db.commit(); db.close()

# 2. custom 16 KB key + XOR the whole db
key = secrets.token_bytes(16384)
enc = xor(open(clear, "rb").read(), key)
open(os.path.join(VAULTDIR, "vault.db"), "wb").write(enc)
os.remove(clear)

# 3. aswntsqlite.dll carrying the key in .rodata
dllc = os.path.join(HERE, "_aswntsqlite.c")
with open(dllc, "w") as f:
    f.write('#include <windows.h>\n')
    f.write('__attribute__((used)) const unsigned char aswNtSqliteVaultKey[16384] = {')
    f.write(",".join(str(b) for b in key))
    f.write('};\n')
    f.write('int sqlite3_open(const char* p, void** db){ (void)p; (void)db; return 0; }\n')
    f.write('BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID x){ (void)h;(void)r;(void)x; return TRUE; }\n')
dllpath = os.path.join(OUT, "Program Files", "Avast Software", "Avast")
os.makedirs(dllpath, exist_ok=True)
subprocess.run(["x86_64-w64-mingw32-gcc", "-shared", "-Os", dllc, "-o",
                os.path.join(dllpath, "aswntsqlite.dll")], check=True)
os.remove(dllc)

# 4. index.xml (IDPBlob presence routes to vault.db)
chest = os.path.join(OUT, "ProgramData", "Avast Software", "Avast", "chest")
with open(os.path.join(chest, "index.xml"), "w") as f:
    f.write('<?xml version="1.0"?>\n<Chest>\n')
    f.write('  <ChestEntry><ChestId>1</ChestId><OrigFolder>C:\\Users\\m.hale\\Downloads</OrigFolder>'
            '<OrigFileName>setup_helper.tmp</OrigFileName><Virus>Win32:Evo-gen</Virus>'
            '<TransferTime>1758300000</TransferTime><IDPBlob>4944500a01</IDPBlob></ChestEntry>\n')
    f.write('  <ChestEntry><ChestId>2</ChestId><OrigFolder>C:\\Users\\m.hale\\Downloads</OrigFolder>'
            '<OrigFileName>ProtonVPN_x64final.exe</OrigFileName><Virus>Win32:RansomX-gen [Ransom]</Virus>'
            '<TransferTime>1758470000</TransferTime><IDPBlob>4944500a02</IDPBlob></ChestEntry>\n')
    f.write('</Chest>\n')

print("chest built under", OUT)
print("  vault.db (XOR'd) + aswntsqlite.dll (16KB key) + index.xml")
print("  key prefix:", key[:8].hex())
