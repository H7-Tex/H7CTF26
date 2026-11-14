import re, struct, sys

OPS = {
    "IMM": (0x01, "r i"), "MOV": (0x02, "r r"), "BP": (0x04, "b a"), "WP": (0x05, "b o l"),
    "CONT": (0x06, ""), "STEP": (0x07, ""), "PEEKREG": (0x08, "r g"), "PEEKMEM": (0x09, "r o"),
    "POKEMEM": (0x0A, "o r"), "JMP": (0x0B, "t"), "JZ": (0x0C, "t"), "JNZ": (0x0D, "t"),
    "JLT": (0x0E, "t"), "SUBMIT": (0x0F, "o l"), "HALT": (0x10, ""),
    "STB": (0x11, "o r"), "STBX": (0x12, "r r"), "LDB": (0x13, "r o"),
    "PEEKMEMX": (0x14, "r r"), "POKEMEMX": (0x15, "r r"),
}
ALU = {"ADD": 0, "SUB": 1, "XOR": 2, "AND": 3, "OR": 4, "SHL": 5, "SHR": 6, "CMP": 7}
REG = {"r%d" % i: i for i in range(8)}
REGID = {"rax": 0, "rcx": 1, "rdx": 2, "rsi": 6, "rdi": 7, "rip": 16}


def enc_reg(t):
    if t not in REG:
        raise ValueError("bad reg %r" % t)
    return REG[t]


def as_int(t, labels):
    t = t.strip()
    if t in labels:
        return labels[t]
    if t.startswith("0x"):
        return int(t, 16)
    return int(t)


def size(op, args):
    if op == "ALU":
        return 4
    _code, spec = OPS[op]
    n = 1
    for s in spec.split():
        n += {"r": 1, "b": 1, "g": 1, "l": 1, "o": 2, "a": 8, "i": 8, "t": 2}[s]
    return n


def assemble(text):
    lines = []
    for raw in text.splitlines():
        line = raw.split(chr(35), 1)[0].strip()
        if line:
            lines.append(line)
    labels, pc, insns = {}, 0, []
    for line in lines:
        m = re.match(r"^(\w+):$", line)
        if m:
            labels[m.group(1)] = pc
            continue
        parts = re.split(r"[ ,]+", line)
        op = parts[0].upper()
        args = parts[1:]
        if op == "ALU":
            insns.append(("ALU", args)); pc += 4
        elif op in OPS:
            insns.append((op, args)); pc += size(op, args)
        else:
            raise ValueError("bad op %r" % op)
    out = bytearray()
    for op, args in insns:
        if op == "ALU":
            sub = ALU[args[0].upper()]; d = enc_reg(args[1]); s = enc_reg(args[2])
            out += bytes([0x03, sub, d, s]); continue
        code, spec = OPS[op]; out.append(code)
        ai = 0
        for s in spec.split():
            a = args[ai]; ai += 1
            if s == "r":
                out.append(enc_reg(a))
            elif s == "b":
                out.append(int(a))
            elif s == "g":
                out.append(REGID[a])
            elif s == "l":
                out.append(int(a))
            elif s == "o":
                out += struct.pack("<H", as_int(a, labels))
            elif s in ("a", "i"):
                out += struct.pack("<Q", as_int(a, labels))
            elif s == "t":
                out += struct.pack("<H", labels[a] if a in labels else int(a))
    return bytes(out)


if __name__ == "__main__":
    src = open(sys.argv[1]).read()
    code = assemble(src)
    framed = struct.pack("<I", len(code)) + code
    out = sys.argv[2] if len(sys.argv) > 2 else sys.argv[1].rsplit(".", 1)[0] + ".bin"
    open(out, "wb").write(framed)
    sys.stderr.write("assembled %d bytes -> %s\n" % (len(code), out))
