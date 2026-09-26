import struct

W = 256
FH = 32
GH = 8
NSUB = 8
PLANE_SIZE = W * FH // 8
MAGIC = b"PDPX"


def u32(x):
    return x & 0xFFFFFFFF


def u16(x):
    return x & 0xFFFF


def derive(seed):
    x = u32(seed)
    x = u32(x ^ 0x5BD1E995)
    x = u32(x * 0x9E3779B1)
    x = u32(x ^ (x >> 15))
    x = u32(x * 0x85EBCA77)
    x = u32(x ^ (x >> 13))
    return x


def lfsr_next(s):
    bit = ((s >> 15) ^ (s >> 13) ^ (s >> 12) ^ (s >> 10)) & 1
    return ((s << 1) | bit) & 0xFFFF


class Schedule:
    def __init__(self, rkey):
        self.rkey = u32(rkey)
        s = ((self.rkey ^ (self.rkey >> 16)) & 0xFFFF) or 0xBEEF
        self.state = s
        perm = list(range(NSUB))
        for i in range(NSUB - 1, 0, -1):
            j = self._byte() % (i + 1)
            perm[i], perm[j] = perm[j], perm[i]
        self.perm = perm
        self.inv = [self._byte() & 1 for _ in range(NSUB)]
        self.off = [((self._byte() % 5) - 2, (self._byte() % 5) - 2) for _ in range(NSUB)]
        self.weight = [1 << self.perm[s] for s in range(NSUB)]

    def _adv(self):
        self.state = lfsr_next(self.state)
        return self.state

    def _byte(self):
        return self._adv() & 0xFF


def keystream(rkey, s, n):
    st = u32(rkey ^ u32(0x01000193 * (s + 1)))
    out = bytearray(n)
    for i in range(n):
        st = u32(st * 1664525 + 1013904223)
        out[i] = (st >> 24) & 0xFF
    return bytes(out)


def build_header(seed):
    return struct.pack("<4sHHHHIH", MAGIC, W, FH, GH, NSUB, seed & 0xFFFFFFFF, PLANE_SIZE)
