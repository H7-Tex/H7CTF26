import os
import socket
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ASM = os.path.join(HERE, os.pardir, "challenge", "interrogator", "asm.py")
TQA = os.path.join(HERE, "optimal.tqa")


def build_submission():
    fd, out = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    subprocess.run([sys.executable, ASM, TQA, out], check=True)
    with open(out, "rb") as f:
        data = f.read()
    os.unlink(out)
    return data


def submit(host, port, payload):
    s = socket.create_connection((host, port), timeout=120)
    s.sendall(payload)
    s.settimeout(120)
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    return buf.decode(errors="replace").strip()


def main():
    if len(sys.argv) < 3:
        print("usage: solve.py HOST PORT")
        sys.exit(2)
    payload = build_submission()
    print(submit(sys.argv[1], int(sys.argv[2]), payload))


if __name__ == "__main__":
    main()
