import sys

PRELOOP = sys.argv[1] if len(sys.argv) > 1 else "0x40301a"
CONFESS = sys.argv[2] if len(sys.argv) > 2 else "0x403019"
OUT = sys.argv[3] if len(sys.argv) > 3 else "optimal.tqa"

L = []
def emit(s): L.append(s)

emit("    IMM r5, 16")
emit("    IMM r4, 255")
emit("    BP 0, %s" % PRELOOP)
emit("    CONT")
emit("    IMM r7, 0")
emit("SCAN:")
emit("    MOV r2, r7")
emit("    IMM r3, 3")
emit("    ALU SHL r2, r3")
emit("    IMM r3, 512")
emit("    ALU ADD r3, r2")
emit("    PEEKMEMX r0, r3")
emit("    MOV r2, r7")
emit("    IMM r3, 3")
emit("    ALU SHL r2, r3")
emit("    IMM r3, 256")
emit("    ALU ADD r3, r2")
emit("    PEEKMEMX r1, r3")
for j in range(8):
    emit("    MOV r2, r0")
    if j:
        emit("    IMM r3, %d" % (8 * j))
        emit("    ALU SHR r2, r3")
    emit("    ALU AND r2, r4")
    emit("    ALU CMP r2, r5")
    emit("    JLT store_j%d" % j)
    emit("    JMP after_j%d" % j)
    emit("store_j%d:" % j)
    emit("    MOV r6, r1")
    if j:
        emit("    IMM r3, %d" % (8 * j))
        emit("    ALU SHR r6, r3")
    emit("    ALU AND r6, r4")
    emit("    STBX r2, r6")
    emit("after_j%d:" % j)
emit("    IMM r3, 1")
emit("    ALU ADD r7, r3")
emit("    IMM r3, 32")
emit("    ALU CMP r7, r3")
emit("    JLT SCAN")

def load_word(base, dst, tmp1, tmp2):
    emit("    IMM %s, 0" % dst)
    for k in range(8):
        emit("    LDB %s, %d" % (tmp1, base + k))
        if k:
            emit("    IMM %s, %d" % (tmp2, 8 * k))
            emit("    ALU SHL %s, %s" % (tmp1, tmp2))
        emit("    ALU OR %s, %s" % (dst, tmp1))

load_word(0, "r0", "r1", "r3")
emit("    POKEMEM 256, r0")
load_word(8, "r0", "r1", "r3")
emit("    POKEMEM 264, r0")

emit("    IMM r0, 0x0706050403020100")
emit("    POKEMEM 512, r0")
emit("    IMM r0, 0x0f0e0d0c0b0a0908")
emit("    POKEMEM 520, r0")
emit("    IMM r0, 16")
emit("    POKEMEM 1024, r0")

emit("    BP 1, %s" % CONFESS)
for k in range(16):
    emit("    CONT")
    emit("    PEEKREG r0, rdi")
    emit("    PEEKREG r1, rsi")
    emit("    IMM r2, 256")
    emit("    ALU ADD r1, r2")
    emit("    STBX r1, r0")
emit("    SUBMIT 256, 16")
emit("    HALT")

open(OUT, "w").write("\n".join(L) + "\n")
sys.stderr.write("wrote %s (%d lines)\n" % (OUT, len(L)))
