import { createVerify, createPublicKey, KeyObject, randomBytes } from 'crypto';
import { decode as cborDecode } from 'cbor2';

const RP_ID = 'harbor.city';

// build SubjectPublicKeyInfo DER for P-256 from uncompressed point (04 || x || y)
function buildP256Spki(uncompressed: Buffer): Buffer {
  // P-256 SPKI prefix: SEQUENCE { SEQUENCE { OID ecPublicKey, OID P-256 }, BIT STRING }
  const prefix = Buffer.from(
    '3059301306072a8648ce3d020106082a8648ce3d030107034200',
    'hex'
  );
  return Buffer.concat([prefix, uncompressed]);
}

// parse COSE P-256 key from CBOR-decoded map and return Node KeyObject + raw SPKI
export function coseKeyToNodeKey(coseMap: Map<number, Uint8Array>): { keyObj: KeyObject; spki: string } {
  const x = coseMap.get(-2);
  const y = coseMap.get(-3);
  if (!x || !y) throw new Error('HARBORID-COSE-01: missing x/y coordinates in COSE key');
  const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);
  const spkiBuf = buildP256Spki(uncompressed);
  const keyObj = createPublicKey({ key: spkiBuf, format: 'der', type: 'spki' });
  return { keyObj, spki: spkiBuf.toString('base64url') };
}

// reconstruct Node KeyObject from stored base64url SPKI
export function spkiToKeyObj(spkiB64: string): KeyObject {
  const der = Buffer.from(spkiB64, 'base64url');
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

// verify ES256 signature: sig over authData || SHA256(clientDataJSON)
export function verifyES256(keyObj: KeyObject, authData: Buffer, clientDataJsonBytes: Buffer, sigDer: Buffer): boolean {
  const hash = createHash('SHA256').update(clientDataJsonBytes).digest();
  const message = Buffer.concat([authData, hash]);
  const v = createVerify('SHA256');
  v.update(message);
  try {
    return v.verify(keyObj, sigDer);
  } catch {
    return false;
  }
}

// parse attestation: returns { authData, coseKey, credId }
export function parseAttestationObject(attObjB64: string): {
  authData: Buffer;
  coseKey: Map<number, Uint8Array>;
  credId: Buffer;
} {
  const attObj = cborDecode(Buffer.from(attObjB64, 'base64url')) as Record<string, unknown>;
  const authData = Buffer.from(attObj['authData'] as Uint8Array);

  // authData: rpIdHash(32) + flags(1) + signCount(4) + AAGUID(16) + credIdLen(2) + credId(N) + coseKey
  if (authData.length < 55) throw new Error('HARBORID-AUTH-01: authenticatorData too short');
  const credIdLen = authData.readUInt16BE(53);
  const credId = authData.subarray(55, 55 + credIdLen);
  const coseKeyBytes = authData.subarray(55 + credIdLen);
  const coseKey = cborDecode(coseKeyBytes) as Map<number, Uint8Array>;
  return { authData, coseKey, credId };
}

// verify a registration clientDataJSON
export function verifyClientDataCreate(b64: string, challenge: string): void {
  let parsed: { type: string; challenge: string; origin: string };
  try {
    parsed = JSON.parse(Buffer.from(b64, 'base64url').toString());
  } catch {
    throw new Error('HARBORID-CDATA-01: clientDataJSON parse failed');
  }
  if (parsed.type !== 'webauthn.create') throw new Error('HARBORID-CDATA-02: wrong type');
  if (parsed.challenge !== challenge) throw new Error('HARBORID-CDATA-03: challenge mismatch');
}

// verify an assertion clientDataJSON
export function verifyClientDataGet(b64: string, challenge: string): void {
  let parsed: { type: string; challenge: string; origin: string };
  try {
    parsed = JSON.parse(Buffer.from(b64, 'base64url').toString());
  } catch {
    throw new Error('HARBORID-CDATA-04: clientDataJSON parse failed');
  }
  if (parsed.type !== 'webauthn.get') throw new Error('HARBORID-CDATA-05: wrong type');
  if (parsed.challenge !== challenge) throw new Error('HARBORID-CDATA-06: challenge mismatch');
}

// verify authenticatorData flags and rpIdHash
export function verifyAuthData(authData: Buffer): void {
  const rpHash = createHash('SHA256').update(RP_ID).digest();
  if (!authData.subarray(0, 32).equals(rpHash)) {
    throw new Error('HARBORID-AUTH-02: RP ID hash mismatch');
  }
  const flags = authData[32];
  if (!(flags & 0x01)) throw new Error('HARBORID-AUTH-03: user presence not set');
}

// small helper - import here to avoid missing import error
import { createHash } from 'crypto';

export { randomBytes };
