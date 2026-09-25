import os
import signal
import sys

from hdl import parse, simulate
from verifier import certify

A_AUDIT = 0xDEADBEEF
MAGIC = 0xB105F00D

HERE = os.path.dirname(os.path.abspath(__file__))
REFERENCE = open(os.path.join(HERE, "reference.hdl")).read()
FLAG = os.environ.get("FLAG", "H7CTF{local_test_flag}")

MAX_BYTES = 64 * 1024
MAX_LINES = 400


def out(s):
    sys.stdout.write(s + "\n")
    sys.stdout.flush()


def read_submission():
    lines = []
    total = 0
    for line in sys.stdin:
        if line.rstrip("\n") == "END":
            break
        total += len(line)
        if total > MAX_BYTES or len(lines) > MAX_LINES:
            raise ValueError("submission too large")
        lines.append(line)
    return "".join(lines)


def main():
    signal.alarm(40)
    out("=== FoundryProof :: combinational equivalence sign-off ===")
    out("Submit a Tiny-HDL netlist (see the handout for the grammar).")
    out(f"It is certified against the golden reference, then audited at A = 0x{A_AUDIT:08X}.")
    out(f"Ship a certified design whose output at the audit vector is 0x{MAGIC:08X}.")
    out("End your netlist with a line containing only: END")
    out("")

    try:
        src = read_submission()
        sub = parse(src)
    except Exception as e:
        out("parse error: " + str(e))
        return

    try:
        certified = certify(REFERENCE, src)
    except Exception as e:
        out("verifier error: " + str(e))
        return

    if not certified:
        out("REJECTED: not equivalent to the golden reference over the sample range.")
        return

    out("CERTIFIED: equivalent to the golden reference.")
    val = simulate(sub, A_AUDIT)
    out(f"audit: T(0x{A_AUDIT:08X}) = 0x{val:08X}")
    if val == MAGIC:
        out("sign-off compromised -- a certified design carries a trojan.")
        out(FLAG)
    else:
        out("audit nominal: honest part, no anomaly. no flag.")


if __name__ == "__main__":
    main()
