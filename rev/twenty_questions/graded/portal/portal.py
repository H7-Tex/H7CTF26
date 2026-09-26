import os, socket, struct, threading
from urllib.parse import urlparse

GRADER = os.environ.get("GRADER", "http://grader:9000")
u = urlparse(GRADER)
GHOST, GPORT = u.hostname, u.port or 9000
LPORT = int(os.environ.get("PORT", "1337"))
MAX_PROG = 4096


def relay(conn):
    try:
        hdr = b""
        while len(hdr) < 4:
            c = conn.recv(4 - len(hdr))
            if not c:
                return
            hdr += c
        n = struct.unpack("<I", hdr)[0]
        if n > MAX_PROG:
            conn.sendall(b'{"solved":false,"err":"program too large"}\n')
            return
        body = b""
        while len(body) < n:
            c = conn.recv(n - len(body))
            if not c:
                return
            body += c
        g = socket.create_connection((GHOST, GPORT), timeout=90)
        g.sendall(hdr + body)
        while True:
            d = g.recv(4096)
            if not d:
                break
            conn.sendall(d)
        g.close()
    except Exception:
        pass
    finally:
        conn.close()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", LPORT))
    s.listen(128)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=relay, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
