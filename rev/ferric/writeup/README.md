# Ferric - writeup

A Rust crackme. Same class of per-byte transform as the C ones, but the point is reversing a **Rust**
binary: monomorphized iterator chains (`.iter().enumerate().all(...)`, `.map().collect()`), `wrapping_*`
arithmetic and `rotate_left` intrinsics, `String`/`Vec` machinery, panic/format glue, and mangled or
(here) stripped symbols. It looks nothing like the tidy C loops in Warden/Interlock.

## The check
`check()` verifies, for each byte:
```
(license[i] ^ XK[i]).rotate_left(ROT[i]).wrapping_add(YA[i]) == TARGET[i]
```
`XK`, `ROT`, `YA`, `TARGET` are `const [u8;16]` arrays in `.rodata`.

## Invert it
Every step is invertible:
```
license[i] = ror8((TARGET[i] - YA[i]) & 0xff, ROT[i]) ^ XK[i]   ->  FERRIC-RUST-KEY1
```

## The token
On a valid license the binary XOR-decrypts `BLOB` with a license-derived keystream:
```
flag[i] = BLOB[i] ^ license[i % 16] ^ ((i*131 + 7) & 0xff)
```
`H7CTF{rust_b1n_r3v_f3rr1c_cr4ckm3}`. `solution/solve.py` inverts + decrypts off the constants.

## Build
`python3 challenge/gen.py` (writes `data.rs`) then
`rustc -O -C strip=symbols challenge/ferric.rs -o challenge/ferric`. `ferric.zip` is the handout.

## Teaching
Reversing Rust binaries specifically - recognising iterator-chain codegen and `wrapping`/`rotate`
intrinsics, and pulling `const` tables out of a Rust `.rodata`. Rounds out the rev set's fifth distinct
skill: Warden (VM), Tollgate (Go), Interlock (linear algebra), Cipherlock (SMT), Ferric (Rust).
