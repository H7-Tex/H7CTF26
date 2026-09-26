import json, os, socket, struct, subprocess, threading
import report

HOST = "0.0.0.0"
PORT = int(os.environ.get("GRADER_PORT", "9000"))
INTERROGATOR = os.environ.get("TQ_INTERROGATOR", "/tq/interrogator")
MAX_PROG = 4096


def recv_prog(conn):
    hdr = b""
    while len(hdr) < 4:
        c = conn.recv(4 - len(hdr))
        if not c:
            return None
        hdr += c
    n = struct.unpack("<I", hdr)[0]
    if n > MAX_PROG:
        return None
    body = b""
    while len(body) < n:
        c = conn.recv(n - len(body))
        if not c:
            return None
        body += c
    return hdr + body


def handle(conn):
    try:
        framed = recv_prog(conn)
        if framed is None:
            conn.sendall(b'{"solved":false,"err":"bad frame"}\n')
            return
        env = dict(os.environ)
        env["TQ_MODE"] = "live"
        p = subprocess.run([INTERROGATOR], input=framed, capture_output=True, env=env, timeout=60)
        out = p.stdout.decode(errors="replace").strip()
        try:
            res = json.loads(out)
        except Exception:
            conn.sendall(b'{"solved":false,"err":"scorer failure"}\n')
            return
        if res.get("solved"):
            st, body = report.report(float(res.get("score", 0.0)), int(res.get("gas", 0)))
            res["report_status"] = st
            res["report"] = body
        conn.sendall((json.dumps(res) + "\n").encode())
    except Exception as e:
        try:
            conn.sendall((json.dumps({"solved": False, "err": str(e)}) + "\n").encode())
        except Exception:
            pass
    finally:
        conn.close()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(64)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
