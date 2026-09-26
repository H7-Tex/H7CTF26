import struct
import hashlib
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"KSHD"
VERSION = 1
FLAG_START = 1
FLAG_TERMINAL = 2
FLAG_DECOY = 4
HEADER_LEN = 50


def shard_key(secret8):
    return hashlib.sha256(bytes(secret8)).digest()


def subkey(base, label):
    return hashlib.sha256(base + label).digest()


def ctr(key, data):
    c = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16)).encryptor()
    return c.update(data) + c.finalize()


def enc_perm(prev_key, perm):
    return ctr(subkey(prev_key, b"PERM"), perm)


def dec_perm(prev_key, blob):
    return ctr(subkey(prev_key, b"PERM"), blob)


def enc_ptr(self_key, next_id):
    return ctr(subkey(self_key, b"PTR"), next_id)


def dec_ptr(self_key, blob):
    return ctr(subkey(self_key, b"PTR"), blob)


def perm_checksum(perm):
    return zlib.crc32(perm) & 0xFFFFFFFF


def pack(self_id, flags, free_bits, perm_stored, perm_plain, next_ptr_ct, sbox, prog):
    assert len(self_id) == 16
    assert len(sbox) == 256
    perm_crc = perm_checksum(perm_plain)
    hdr = MAGIC + struct.pack(
        "<BBBBHHBB",
        VERSION,
        flags,
        free_bits,
        8,
        len(perm_stored),
        len(prog),
        0,
        0,
    )
    hdr += self_id
    hdr += struct.pack("<I", perm_crc)
    hdr += next_ptr_ct
    assert len(hdr) == HEADER_LEN, len(hdr)
    return hdr + perm_stored + bytes(sbox) + prog


def parse(blob):
    assert blob[:4] == MAGIC
    version, flags, free_bits, nsec, perm_len, prog_len, _r0, _r1 = struct.unpack_from(
        "<BBBBHHBB", blob, 4
    )
    self_id = blob[14:30]
    perm_crc = struct.unpack_from("<I", blob, 30)[0]
    next_ptr_ct = blob[34:50]
    off = HEADER_LEN
    perm_stored = blob[off : off + perm_len]
    off += perm_len
    sbox = blob[off : off + 256]
    off += 256
    prog = blob[off : off + prog_len]
    return {
        "flags": flags,
        "free_bits": free_bits,
        "self_id": self_id,
        "perm_crc": perm_crc,
        "next_ptr_ct": next_ptr_ct,
        "perm_stored": perm_stored,
        "sbox": bytes(sbox),
        "prog": prog,
    }
