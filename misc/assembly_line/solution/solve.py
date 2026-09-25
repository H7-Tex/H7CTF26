#!/usr/bin/env python3
# Solver for Assembly Line: parse each task, compute, reply - fast enough to clear 250 rounds at 2s each.
import sys, socket, base64, re

def answer(prompt):
    if prompt.startswith("eval: "):
        a, op, b = prompt[6:].split()
        return str(eval(f"{a}{op}{b}"))
    if prompt.startswith("reverse: "):
        return prompt[9:][::-1]
    if prompt.startswith("sum: "):
        return str(sum(int(x) for x in prompt[5:].split(",")))
    if prompt.startswith("b64: "):
        return base64.b64decode(prompt[5:]).decode()
    return ""

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    s = socket.create_connection((host, port), timeout=10)
    f = s.makefile("rwb")
    for line in f:
        t = line.decode(errors="replace").strip()
        m = re.match(r"\[\d+/\d+\]\s+(.*)", t)
        if m:
            f.write((answer(m.group(1)) + "\n").encode()); f.flush()
        elif "H7CTF{" in t:
            print(t); break
        elif "wrong" in t:
            print("failed:", t); break
    s.close()

if __name__ == "__main__":
    main()
