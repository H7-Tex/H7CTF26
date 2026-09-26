import struct

HALT = 0
LDS = 1
LDI = 2
MOV = 3
XOR = 4
ADD = 5
MUL = 6
AND = 7
OR = 8
ROL = 9
SBOX = 10
ASSERT = 11
ANDI = 12
XORI = 13

WIDTH = {
    HALT: 1,
    LDS: 3,
    LDI: 6,
    MOV: 3,
    XOR: 3,
    ADD: 3,
    MUL: 3,
    AND: 3,
    OR: 3,
    ROL: 3,
    SBOX: 3,
    ASSERT: 6,
    ANDI: 6,
    XORI: 6,
}

MASK = 0xFFFFFFFF


def rol32(v, c):
    c &= 31
    return ((v << c) | (v >> (32 - c))) & MASK


class Program:
    def __init__(self):
        self.code = bytearray()

    def _emit(self, *bs):
        for b in bs:
            self.code.append(b & 0xFF)

    def lds(self, rd, idx):
        self._emit(LDS, rd, idx)

    def ldi(self, rd, imm):
        self._emit(LDI, rd)
        self.code += struct.pack("<I", imm & MASK)

    def mov(self, rd, rs):
        self._emit(MOV, rd, rs)

    def xor(self, rd, rs):
        self._emit(XOR, rd, rs)

    def add(self, rd, rs):
        self._emit(ADD, rd, rs)

    def mul(self, rd, rs):
        self._emit(MUL, rd, rs)

    def and_(self, rd, rs):
        self._emit(AND, rd, rs)

    def or_(self, rd, rs):
        self._emit(OR, rd, rs)

    def rol(self, rd, c):
        self._emit(ROL, rd, c)

    def sbox(self, rd, rs):
        self._emit(SBOX, rd, rs)

    def andi(self, rd, imm):
        self._emit(ANDI, rd)
        self.code += struct.pack("<I", imm & MASK)

    def xori(self, rd, imm):
        self._emit(XORI, rd)
        self.code += struct.pack("<I", imm & MASK)

    def assert_(self, rs, imm):
        self._emit(ASSERT, rs)
        self.code += struct.pack("<I", imm & MASK)

    def halt(self):
        self._emit(HALT)

    def bytes(self):
        return bytes(self.code)


def trace_regs(code, sbox_tab, secret):
    regs = [0] * 8
    ip = 0
    n = len(code)
    while ip < n:
        op = code[ip]
        if op == HALT:
            break
        if op == LDS:
            regs[code[ip + 1]] = secret[code[ip + 2]] & 0xFF
            ip += 3
        elif op == LDI:
            regs[code[ip + 1]] = struct.unpack_from("<I", code, ip + 2)[0]
            ip += 6
        elif op == MOV:
            regs[code[ip + 1]] = regs[code[ip + 2]]
            ip += 3
        elif op == XOR:
            regs[code[ip + 1]] ^= regs[code[ip + 2]]
            ip += 3
        elif op == ADD:
            rd = code[ip + 1]
            regs[rd] = (regs[rd] + regs[code[ip + 2]]) & MASK
            ip += 3
        elif op == MUL:
            rd = code[ip + 1]
            regs[rd] = (regs[rd] * regs[code[ip + 2]]) & MASK
            ip += 3
        elif op == AND:
            regs[code[ip + 1]] &= regs[code[ip + 2]]
            ip += 3
        elif op == OR:
            regs[code[ip + 1]] |= regs[code[ip + 2]]
            ip += 3
        elif op == ROL:
            rd = code[ip + 1]
            regs[rd] = rol32(regs[rd], code[ip + 2])
            ip += 3
        elif op == SBOX:
            regs[code[ip + 1]] = sbox_tab[regs[code[ip + 2]] & 0xFF]
            ip += 3
        elif op == ANDI:
            rd = code[ip + 1]
            regs[rd] &= struct.unpack_from("<I", code, ip + 2)[0]
            ip += 6
        elif op == XORI:
            rd = code[ip + 1]
            regs[rd] ^= struct.unpack_from("<I", code, ip + 2)[0]
            ip += 6
        elif op == ASSERT:
            ip += 6
        else:
            raise ValueError("bad opcode")
    return regs


def permute_opcodes(code, enc):
    out = bytearray(code)
    ip = 0
    n = len(code)
    while ip < n:
        op = code[ip]
        out[ip] = enc[op]
        ip += WIDTH[op]
    return bytes(out)


def permute_opcodes_dec(stored, dec):
    out = bytearray(stored)
    ip = 0
    n = len(stored)
    while ip < n:
        op = dec[stored[ip]]
        out[ip] = op
        ip += WIDTH[op]
    return bytes(out)


def run(code, sbox_tab, secret):
    regs = [0] * 8
    ip = 0
    n = len(code)
    while ip < n:
        op = code[ip]
        if op == HALT:
            break
        if op == LDS:
            rd = code[ip + 1]
            idx = code[ip + 2]
            regs[rd] = secret[idx] & 0xFF
            ip += 3
        elif op == LDI:
            rd = code[ip + 1]
            imm = struct.unpack_from("<I", code, ip + 2)[0]
            regs[rd] = imm
            ip += 6
        elif op == MOV:
            regs[code[ip + 1]] = regs[code[ip + 2]]
            ip += 3
        elif op == XOR:
            regs[code[ip + 1]] ^= regs[code[ip + 2]]
            ip += 3
        elif op == ADD:
            rd = code[ip + 1]
            regs[rd] = (regs[rd] + regs[code[ip + 2]]) & MASK
            ip += 3
        elif op == MUL:
            rd = code[ip + 1]
            regs[rd] = (regs[rd] * regs[code[ip + 2]]) & MASK
            ip += 3
        elif op == AND:
            regs[code[ip + 1]] &= regs[code[ip + 2]]
            ip += 3
        elif op == OR:
            regs[code[ip + 1]] |= regs[code[ip + 2]]
            ip += 3
        elif op == ROL:
            rd = code[ip + 1]
            regs[rd] = rol32(regs[rd], code[ip + 2])
            ip += 3
        elif op == SBOX:
            regs[code[ip + 1]] = sbox_tab[regs[code[ip + 2]] & 0xFF]
            ip += 3
        elif op == ANDI:
            rd = code[ip + 1]
            imm = struct.unpack_from("<I", code, ip + 2)[0]
            regs[rd] &= imm
            ip += 6
        elif op == XORI:
            rd = code[ip + 1]
            imm = struct.unpack_from("<I", code, ip + 2)[0]
            regs[rd] ^= imm
            ip += 6
        elif op == ASSERT:
            rs = code[ip + 1]
            imm = struct.unpack_from("<I", code, ip + 2)[0]
            if regs[rs] != imm:
                return False
            ip += 6
        else:
            raise ValueError("bad opcode")
    return True
