#!/usr/bin/env python3
# Assembly Line - a package-sorting line. Answer 250 quick tasks in a row, each within 2 seconds.
# No human types that fast for that long -> you must script a client. Finish the line -> flag.
import os, random, socketserver, base64, string

ROUNDS = 250
FLAG = os.environ.get("FLAG", "H7CTF{sp33d_run_th3_4ss3mbly_l1n3_w1th_c0d3}")

def make_task(rng):
    kind = rng.choice(["eval", "reverse", "sum", "b64"])
    if kind == "eval":
        a, b = rng.randint(1000, 99999), rng.randint(1000, 99999)
        op = rng.choice(["+", "-", "*"])
        return f"eval: {a} {op} {b}", str(eval(f"{a}{op}{b}"))
    if kind == "reverse":
        s = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(rng.randint(8, 20)))
        return f"reverse: {s}", s[::-1]
    if kind == "sum":
        nums = [rng.randint(1, 9999) for _ in range(rng.randint(5, 15))]
        return f"sum: {','.join(map(str, nums))}", str(sum(nums))
    raw = "".join(rng.choice(string.ascii_letters) for _ in range(rng.randint(6, 16)))
    return f"b64: {base64.b64encode(raw.encode()).decode()}", raw

class Handler(socketserver.StreamRequestHandler):
    timeout = 2                                   # per-read: 2s -> manual can't keep up for 250 rounds
    def handle(self):
        rng = random.Random()
        self.wfile.write(b"=== Sparrow Freight sorting line ===\n")
        self.wfile.write(f"answer {ROUNDS} tasks, 2s each. go.\n".encode())
        try:
            for i in range(ROUNDS):
                prompt, answer = make_task(rng)
                self.wfile.write(f"[{i+1}/{ROUNDS}] {prompt}\n".encode())
                line = self.rfile.readline()
                if not line or line.decode(errors="replace").strip() != answer:
                    self.wfile.write(b"wrong / too slow. line stopped.\n")
                    return
            self.wfile.write(f"line cleared! {FLAG}\n".encode())
        except Exception:
            return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "9999"))
    Server(("0.0.0.0", port), Handler).serve_forever()
