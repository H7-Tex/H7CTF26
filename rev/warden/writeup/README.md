# Warden - writeup

A crackme built around a custom bytecode VM. The binary won't hand over the flag until you
feed it a license key it accepts, and the accept condition is decided by an interpreter, not a
plain comparison - so you have to reverse the VM, not just the check.

## 1. Recon
`warden` is a small stripped x86-64 ELF. Run it: it asks for a `license key:`, and any 16-char
guess prints `license rejected`. `strings` shows the prompts and `license accepted. provisioning:
%s` but **no flag** - the flag is encrypted in `.rodata`.

The `main` logic: read 16 bytes, call a validator, and only on success derive an AES key and
decrypt a blob. So two things to beat: the validator, and the crypto.

## 2. The VM
The validator doesn't branch on the input directly. It walks a byte array (`BYTECODE` in
`.rodata`) with a dispatch loop over a small opcode set, pushing/popping an 8-bit stack:

| op | meaning |
|----|---------|
| 01 | PUSH_INPUT idx - push `license[idx]` |
| 02 | PUSH_IMM b - push constant `b` |
| 03 | XOR - push `pop ^ pop` |
| 04 | ADD - push `(pop + pop) & 0xff` |
| 05 | ROL n - push `rotate_left(pop, n)` |
| 06 | CMP_IMM b - pop; if `!= b` mark failure |
| 00 | HALT |

The bytecode is 16 identical blocks, one per key byte:

```
01 i    PUSH_INPUT i
02 X    PUSH_IMM  X[i]
03      XOR                 -> license[i] ^ X[i]
02 Y    PUSH_IMM  Y[i]
04      ADD                 -> (license[i] ^ X[i]) + Y[i]
05 R    ROL       R[i]
06 T    CMP_IMM   T[i]      -> must equal target[i]
```

So the per-byte check is `rol8((license[i] ^ X[i]) + Y[i], R[i]) == T[i]`, with `X`, `Y`, `R`,
`T` all baked into the bytecode as immediates.

## 3. Invert it
Every step is invertible, so there's exactly one key - no search:

```
license[i] = (ror8(T[i], R[i]) - Y[i]) & 0xff) ^ X[i]
```

Pull `X`, `Y`, `R`, `T` out of each block (dump `.rodata`, or match the block structure
`01 . 02 . 03 02 . 04 05 . 06 .`) and you get `H7X-9F2A-COREKEY`.

## 4. The flag
On success the binary does `key = MD5(license)`, then AES-128-CBC decrypt (zero IV, PKCS7) of the
48-byte blob sitting just before the bytecode in `.rodata`. Either feed the recovered key to the
binary, or decrypt offline. `solution/solve.py` does the whole thing off the handout binary:
locate the bytecode, invert the transform, `MD5` + AES -> flag.

`H7CTF{cust0m_vm_l1c3ns3_w4rd3n_r3v}`

## Build
`python3 challenge/gen.py` (emits `warden_data.h`) then
`gcc challenge/warden.c -o challenge/warden -lcrypto -Os -s`. `warden` is the handout.

## Teaching / realism
Custom bytecode VMs are a real obfuscation for license checks, DRM, and packers - the reverser's
job is to recover the interpreter's semantics, not any single algorithm. This one is deliberately
small and fully invertible so the payoff is "reverse the machine, then invert the math," not a
brute force.
