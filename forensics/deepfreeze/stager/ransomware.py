#!/usr/bin/env python3
"""Benign ransomware-footprint stager (runs on the throwaway lab VM only).

Reproduces the FORENSIC footprint of a ransomware caught mid-run, with NO malicious
behaviour: it AES-encrypts one decoy document it created itself, drops the .locked file,
and then keeps the key + IV resident in its own memory and sleeps (simulating a process
whose key has not yet been wiped). We then capture the VM's RAM with avml. No spreading,
no network, no touching anything it did not create.
"""
import os, sys, time, struct, zlib
try:
    from Crypto.Cipher import AES
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES

FLAG = os.environ.get("FLAG", "H7CTF{deep_freeze_local_test}")


def minimal_pdf(body_text):
    # a small, valid PDF so the recovered plaintext has the %PDF- magic to lock onto
    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
    stream = b"BT /F1 12 Tf 72 720 Td (" + body_text.encode() + b") Tj ET"
    objs.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    out = b"%PDF-1.4\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += str(i).encode() + b" 0 obj\n" + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 " + str(len(objs) + 1).encode() + b"\n0000000000 65535 f \n"
    for off in offs:
        out += ("%010d 00000 n \n" % off).encode()
    out += b"trailer\n<< /Size " + str(len(objs) + 1).encode() + b" /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF"
    return out


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "/srv/incident"
    os.makedirs(outdir, exist_ok=True)
    plaintext = minimal_pdf(f"CONFIDENTIAL patient record. Recovery token: {FLAG}")
    key = os.urandom(32)
    iv = os.urandom(16)
    pad = 16 - (len(plaintext) % 16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext + bytes([pad]) * pad)
    with open(os.path.join(outdir, "Q3_patient_records.pdf.locked"), "wb") as f:
        f.write(iv + ct)
    # keep key material resident (the "caught mid-run" condition): the raw key/iv
    # (found by a known-plaintext memory search) AND a live cipher object whose
    # expanded round-key schedule stays in the heap (found by aeskeyfind).
    hold_schedule = AES.new(key, AES.MODE_ECB)
    resident = {"aes_key": key, "aes_iv": iv, "cipher": hold_schedule, "note": b"kdmp-resident-do-not-swap"}
    print(f"[stager] locked file written to {outdir}; key resident in PID {os.getpid()}; idling for RAM capture", flush=True)
    while True:
        _ = resident["aes_key"][0]
        _ = resident["cipher"].encrypt(b"\x00" * 16)
        time.sleep(5)


if __name__ == "__main__":
    main()
