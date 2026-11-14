import os
import sys
import json
import base64
import hashlib
import datetime
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

sys.path.insert(0, os.path.dirname(__file__))
from solve import (b64u, cbor, cose_key, auth_data, tlv, POLICY_OID)

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"


def load_known_aaguid():
    path = os.environ.get("MDS_PATH", "/home/abu/Main/Projects/CTF26/H7CTF26/crypto/vouchsafe/challenge/mds_blob.json")
    raw = open(path, "rb").read()
    payload = json.loads(base64.urlsafe_b64decode(raw.split(b".")[1] + b"=="))
    return payload["entries"][0]["aaguid"].replace("-", "")


def bool_field(tag, value):
    return bytes([0x80 | tag]) + b"\x01" + (b"\xff" if value else b"\x00")


def policy_ext(count, fields):
    version = tlv(0x02, b"\x01")
    cnt = tlv(0x02, bytes([count]) if count >= 0 else b"\xff")
    aaguids = tlv(0x30, tlv(0x04, b"\x11" * 16) * max(count, 0))
    return tlv(0x30, version + cnt + aaguids + fields)


def leaf_with(key, ext_value):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime(2023, 1, 1)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
         .public_key(key.public_key()).serial_number(1)
         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650)))
    if ext_value is not None:
        b = b.add_extension(x509.UnrecognizedExtension(POLICY_OID, ext_value), critical=False)
    return b.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


def enroll(fmt, use_x5c, ext_value, aaguid=b"\x00" * 16):
    s = requests.Session()
    begin = s.get(BASE + "/register/begin").json()
    rp_id, origin = begin["rpId"], begin["origin"]
    challenge = base64.urlsafe_b64decode(begin["challenge"] + "==")
    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = os.urandom(16)
    cose = cose_key(key.public_key())
    cd = json.dumps({"type": "webauthn.create", "challenge": b64u(challenge), "origin": origin}, separators=(",", ":")).encode()
    ch = hashlib.sha256(cd).digest()
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    ad = rp_hash + bytes([0x45]) + b"\x00\x00\x00\x00" + aaguid + len(cred_id).to_bytes(2, "big") + cred_id + cbor(cose)
    sig = key.sign(ad + ch, ec.ECDSA(hashes.SHA256()))
    attstmt = {"alg": -7, "sig": sig}
    if use_x5c:
        attstmt["x5c"] = [leaf_with(key, ext_value)]
    att = cbor({"fmt": fmt, "attStmt": attstmt, "authData": ad})
    r = s.post(BASE + "/register/finish", json={"clientDataJSON": b64u(cd), "attestationObject": b64u(att)})
    try:
        tier = r.json().get("tier")
    except Exception:
        tier = None
    return r.status_code, tier


def main():
    known = load_known_aaguid()
    known_bytes = bytes.fromhex(known)
    cases = []

    cases.append(("no-x5c self-attestation", lambda: enroll("packed", False, None)))
    cases.append(("self-enroll no policy ext", lambda: enroll("packed", True, None)))
    cases.append(("self-enroll benign [7]=FALSE count0", lambda: enroll("packed", True, policy_ext(0, bool_field(7, False)))))
    cases.append(("self-enroll [7]=TRUE count0 (cheese attempt)", lambda: enroll("packed", True, policy_ext(0, bool_field(7, True)))))
    cases.append(("self-enroll TRUE at [8] count0 (wrong tag)", lambda: enroll("packed", True, policy_ext(0, bool_field(8, True)))))
    cases.append(("known-AAGUID self-signed + elevated", lambda: enroll("packed", True, policy_ext(1, bool_field(7, False) + bool_field(8, True)), aaguid=known_bytes)))
    cases.append(("tpm self-signed", lambda: enroll("tpm", True, policy_ext(1, bool_field(7, False) + bool_field(8, True)))))
    cases.append(("android-key self-signed", lambda: enroll("android-key", True, policy_ext(1, bool_field(7, False) + bool_field(8, True)))))
    cases.append(("INTENDED count1 [7]=FALSE [8]=TRUE", lambda: enroll("packed", True, policy_ext(1, bool_field(7, False) + bool_field(8, True)))))

    ok = True
    for name, fn in cases:
        code, tier = fn()
        intended = name.startswith("INTENDED")
        reached = (tier == "enterprise")
        verdict = "OK"
        if intended and not reached:
            verdict = "FAIL(expected enterprise)"
            ok = False
        if not intended and reached:
            verdict = "FAIL(unexpected enterprise)"
            ok = False
        print(f"[{verdict}] {name}: status={code} tier={tier}")
    print("UNIQUENESS", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
