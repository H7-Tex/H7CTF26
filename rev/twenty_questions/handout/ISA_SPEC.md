# The Interrogator

The Interrogator is a locked-down forensic debugger. You cannot attach gdb to the sealer. You
express your audit as a program of debug events, submit it, and the Interrogator runs it against a
freshly seeded sealer. Every debug event has a gas cost. Your program must finish within the gas
budget and end with a SUBMIT of the bytes you recovered.

## Wire protocol
Connect over TCP. Send your program as a 4-byte little-endian length followed by that many bytes of
bytecode. The Interrogator replies with one JSON line:

    {"solved": <bool>, "gas": <int>, "score": <float 0..1>, "flag": "<string or empty>", "err": <null or reason>}

- `solved` is true when the 16 bytes you SUBMIT match the sealer's secret core for that run.
- `score` is the relative grade: any correct solve banks a floor, and fewer debug events earns the rest.
- `gas` is what your program spent. Budget: 8000. Program size limit: 4096 bytes.

## Machine model
- 8 general registers `r0`..`r7`, 64-bit.
- 512 bytes of scratch memory, byte addressable, private to your program.
- Two flags set by CMP and by CONT: a zero flag and a less-than flag.
- The sealer runs as a child under the Interrogator. You place code breakpoints by absolute address
  and you read the child's general registers at a stop. You may read and write the sealer's "device
  RAM" window by offset; the window base is fixed for a given sealer build. You cannot read or write
  outside the window, and you cannot read the sealer's stack or code as data.

## Gas
Only debug events (interactions with the child) cost gas. Local register and scratch work is free.

| op | cost |
|----|------|
| BP        | 10 |
| WP        | 20 |
| CONT      | 5  |
| STEP      | 50 |
| PEEKREG   | 1  |
| PEEKMEM   | 2  |
| PEEKMEMX  | 2  |
| POKEMEM   | 4  |
| POKEMEMX  | 4  |
| out-of-window poke | 100 and abort |
| IMM MOV ALU JMP JZ JNZ JLT SUBMIT STB STBX LDB HALT | 0 |

## Instruction set
Operands: `rD`,`rS` are registers; `imm64` is an 8-byte immediate; `addr` is an 8-byte code address;
`off` is a 16-bit window/scratch offset; `regid` selects a child register; `tgt` is a program label.

- `IMM rD, imm64` : rD = imm64
- `MOV rD, rS` : rD = rS
- `ALU op rD, rS` : op in ADD SUB XOR AND OR SHL SHR CMP. CMP sets zero and less-than flags, writes nothing.
- `BP slot, addr` : arm breakpoint `slot` (0..7) at code `addr`
- `WP slot, off, len` : arm a watchpoint slot on the window
- `CONT` : run the child to the next breakpoint. Zero flag set if the child is still stopped, cleared if it exited.
- `STEP` : single step one instruction
- `PEEKREG rD, regid` : rD = child register. regid names: rax rcx rdx rsi rdi rip.
- `PEEKMEM rD, off` : rD = 8 bytes of the window at offset `off`
- `PEEKMEMX rD, rOff` : rD = 8 bytes of the window at the offset held in rOff
- `POKEMEM off, rS` : write 8 bytes rS into the window at offset `off`
- `POKEMEMX rOff, rS` : write 8 bytes rS into the window at the offset held in rOff
- `JMP tgt` / `JZ tgt` / `JNZ tgt` / `JLT tgt` : jump, on zero, on not-zero, on less-than
- `STB off, rS` : scratch[off] = low byte of rS
- `STBX rIdx, rS` : scratch[rIdx & 511] = low byte of rS
- `LDB rD, off` : rD = scratch[off]
- `SUBMIT off, len` : submit scratch[off .. off+len] as your recovered bytes
- `HALT` : stop

## Assembler
`asm.py prog.tqa out.bin` produces the length-prefixed bytecode. Labels are `name:` on their own line.
One instruction per line, `#` starts a comment in your own source. See `example.tqa`.

## Offline
`simulator` is the exact Interrogator you face on the remote, in offline mode: it runs against a local
sealer with a fixed placeholder secret and a fixed seed, so you can develop and measure gas without
spending remote attempts. Set `TQ_SEALER` to the shipped `sealer` path. The remote reseeds every run.
