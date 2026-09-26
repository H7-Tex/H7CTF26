import sys
import struct
import subprocess
import socket

from z3 import BitVec, BitVecVal, RotateLeft, LShR, Extract, ZeroExt, If, Solver, sat

OP_LDI = 0x01
OP_MOV = 0x02
OP_ADD = 0x03
OP_XOR = 0x04
OP_AND = 0x05
OP_OR = 0x06
OP_ROL = 0x07
OP_SHR = 0x08
OP_ADDI = 0x09
OP_XORI = 0x0A
OP_ANDI = 0x0B
OP_LOADIN = 0x0C
OP_LOADFLAG = 0x0D
OP_EMIT = 0x0E
OP_HALT = 0x0F

COND_NONE = 0xFF
INLEN = 24


class Conn:
    def __init__(self, mode, arg):
        if mode == "proc":
            self.p = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
            self.rf = self.p.stdout
            self.wf = self.p.stdin
        else:
            host, port = arg
            self.s = socket.create_connection((host, port))
            self.rf = self.s.makefile("rb")
            self.wf = self.s.makefile("wb")
        self.readline()
        self.readline()

    def readline(self):
        return self.rf.readline().decode().strip()

    def cmd(self, text):
        self.wf.write((text + "\n").encode())
        self.wf.flush()
        return self.readline()


def parse_blob(hexstr):
    b = bytes.fromhex(hexstr)
    assert b[:4] == b"CSGN"
    off = 4
    version = struct.unpack_from("<H", b, off)[0]; off += 2
    nblocks = struct.unpack_from("<H", b, off)[0]; off += 2
    entry = struct.unpack_from("<H", b, off)[0]; off += 2
    nonce = b[off:off + 8]; off += 8
    blocks = {}
    order = []
    for _ in range(nblocks):
        bid = struct.unpack_from("<H", b, off)[0]; off += 2
        cond_reg = b[off]; off += 1
        cond_bit = b[off]; off += 1
        poison_dst = struct.unpack_from("<H", b, off)[0]; off += 2
        code_len = struct.unpack_from("<H", b, off)[0]; off += 2
        code = b[off:off + code_len]; off += code_len
        nedges = b[off]; off += 1
        edges = []
        for _ in range(nedges):
            cond = b[off]; off += 1
            dst = struct.unpack_from("<H", b, off)[0]; off += 2
            salt = struct.unpack_from("<I", b, off)[0]; off += 4
            tag = b[off:off + 6]; off += 6
            edges.append({"cond": cond, "dst": dst, "salt": salt, "tag": tag})
        blk = {"id": bid, "cond_reg": cond_reg, "cond_bit": cond_bit,
               "poison_dst": poison_dst, "code": code, "edges": edges}
        blocks[bid] = blk
        order.append(bid)
    return {"version": version, "entry": entry, "nonce": nonce, "blocks": blocks, "order": order}


def edge_msg(src, dst, cond, salt):
    return struct.pack("<HHB I", src, dst, cond, salt)


def label_edges(conn, prog):
    for bid, blk in prog["blocks"].items():
        for e in blk["edges"]:
            msg = edge_msg(bid, e["dst"], e["cond"], e["salt"])
            resp = conn.cmd("MINT " + msg.hex())
            e["real"] = bytes.fromhex(resp) == e["tag"]


def real_edges(blk):
    return [e for e in blk["edges"] if e["real"]]


def block_has_emit(blk):
    code = blk["code"]
    i = 0
    while i < len(code):
        op = code[i]
        if op == OP_EMIT:
            return True
        i = advance(code, i)
    return False


def advance(code, i):
    op = code[i]
    if op in (OP_LDI, OP_ADDI, OP_XORI, OP_ANDI):
        return i + 6
    if op in (OP_MOV, OP_ADD, OP_XOR, OP_AND, OP_OR, OP_ROL, OP_SHR, OP_LOADIN):
        return i + 3
    return i + 1


def apply_ops(code, r, inbytes):
    r = list(r)
    i = 0
    n = len(code)
    while i < n:
        op = code[i]
        if op == OP_LDI:
            rd = code[i + 1]; imm = struct.unpack_from("<I", code, i + 2)[0]
            r[rd] = BitVecVal(imm, 32); i += 6
        elif op == OP_MOV:
            r[code[i + 1]] = r[code[i + 2]]; i += 3
        elif op == OP_ADD:
            r[code[i + 1]] = r[code[i + 1]] + r[code[i + 2]]; i += 3
        elif op == OP_XOR:
            r[code[i + 1]] = r[code[i + 1]] ^ r[code[i + 2]]; i += 3
        elif op == OP_AND:
            r[code[i + 1]] = r[code[i + 1]] & r[code[i + 2]]; i += 3
        elif op == OP_OR:
            r[code[i + 1]] = r[code[i + 1]] | r[code[i + 2]]; i += 3
        elif op == OP_ROL:
            r[code[i + 1]] = RotateLeft(r[code[i + 1]], code[i + 2] & 31); i += 3
        elif op == OP_SHR:
            sh = code[i + 2]
            r[code[i + 1]] = BitVecVal(0, 32) if sh >= 32 else LShR(r[code[i + 1]], sh)
            i += 3
        elif op == OP_ADDI:
            imm = struct.unpack_from("<I", code, i + 2)[0]
            r[code[i + 1]] = r[code[i + 1]] + BitVecVal(imm, 32); i += 6
        elif op == OP_XORI:
            imm = struct.unpack_from("<I", code, i + 2)[0]
            r[code[i + 1]] = r[code[i + 1]] ^ BitVecVal(imm, 32); i += 6
        elif op == OP_ANDI:
            imm = struct.unpack_from("<I", code, i + 2)[0]
            r[code[i + 1]] = r[code[i + 1]] & BitVecVal(imm, 32); i += 6
        elif op == OP_LOADIN:
            rd = code[i + 1]; ix = code[i + 2]
            r[rd] = ZeroExt(24, inbytes[ix]); i += 3
        else:
            i = advance(code, i)
    return r


def solve(prog):
    blocks = prog["blocks"]
    inbytes = [BitVec("in%d" % i, 8) for i in range(INLEN)]
    r = [BitVecVal(0, 32) for _ in range(8)]
    s = Solver()

    cur = prog["entry"]
    guard = 0
    while True:
        guard += 1
        if guard > 10000:
            raise RuntimeError("cfg walk runaway")
        blk = blocks[cur]
        r = apply_ops(blk["code"], r, inbytes)
        if block_has_emit(blk):
            break
        reals = real_edges(blk)
        dsts = {e["dst"] for e in reals}
        emit_dst = None
        for e in reals:
            if block_has_emit(blocks[e["dst"]]):
                emit_dst = e
                break
        if emit_dst is not None:
            cbit = Extract(blk["cond_bit"], blk["cond_bit"], r[blk["cond_reg"]])
            s.add(cbit == BitVecVal(emit_dst["cond"], 1))
            cur = emit_dst["dst"]
            continue
        if len(reals) == 1 and reals[0]["cond"] == COND_NONE:
            cur = reals[0]["dst"]
            continue
        if len(reals) == 2:
            e0 = [e for e in reals if e["cond"] == 0][0]
            e1 = [e for e in reals if e["cond"] == 1][0]
            cbit = Extract(blk["cond_bit"], blk["cond_bit"], r[blk["cond_reg"]])
            armA = blocks[e0["dst"]]
            armB = blocks[e1["dst"]]
            sA = apply_ops(armA["code"], r, inbytes)
            sB = apply_ops(armB["code"], r, inbytes)
            mA = real_edges(armA)[0]["dst"]
            mB = real_edges(armB)[0]["dst"]
            assert mA == mB
            r = [If(cbit == BitVecVal(0, 1), sA[i], sB[i]) for i in range(8)]
            cur = mA
            continue
        raise RuntimeError("unexpected block shape at %x" % cur)

    if s.check() != sat:
        raise RuntimeError("unsat")
    m = s.model()
    out = bytearray(INLEN)
    for i in range(INLEN):
        out[i] = m[inbytes[i]].as_long() if m[inbytes[i]] is not None else 0
    return bytes(out)


def main():
    if len(sys.argv) >= 3:
        conn = Conn("tcp", (sys.argv[1], int(sys.argv[2])))
    else:
        path = sys.argv[1] if len(sys.argv) == 2 else "./core"
        conn = Conn("proc", [path])

    blob = conn.cmd("GET")
    prog = parse_blob(blob)
    print("[*] blocks: %d entry: %04x" % (len(prog["blocks"]), prog["entry"]))
    label_edges(conn, prog)
    nreal = sum(len(real_edges(b)) for b in prog["blocks"].values())
    ntotal = sum(len(b["edges"]) for b in prog["blocks"].values())
    print("[*] edges labeled via MINT oracle: %d real of %d total" % (nreal, ntotal))
    inp = solve(prog)
    print("[*] solved input: %s" % inp.hex())
    resp = conn.cmd("RUN " + inp.hex())
    print("[+] flag: %s" % resp)


if __name__ == "__main__":
    main()
