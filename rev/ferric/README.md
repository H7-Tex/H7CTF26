# Rust in Peace

**Category:** Rev  **Difficulty:** Medium  **Author:** abu

> A firmware vendor with strong opinions about memory safety shipped this licence validator with every label filed off. Right licence and it surrenders the token; wrong one and it just shrugs.
>
> Safe code still has to answer for what it's guarding.

Handout: `challenge/ferric.zip`

## Solution

The math here is easy. The annoying part is that it's a stripped Rust binary, so the check is buried in iterator chains (`.iter().enumerate().all(...)`), `wrapping_add`, `rotate_left` and a lot of `String`/`Vec`/panic glue. Once you find the closure inside `all()`, each byte is checked as:

```
(license[i] ^ XK[i]).rotate_left(ROT[i]).wrapping_add(YA[i]) == TARGET[i]
```

`XK`, `ROT`, `YA` and `TARGET` are `const [u8; 16]` tables in `.rodata`. The values go through `black_box` so the compiler can't fold it all into a plain compare, but it still inverts byte by byte:

```
license[i] = ror8((TARGET[i] - YA[i]) & 0xff, ROT[i]) ^ XK[i]
```

That gives `FERRIC-RUST-KEY1`. With a valid licence the binary XORs a blob with a key derived from the licence:

```
flag[i] = BLOB[i] ^ license[i % 16] ^ ((i*131 + 7) & 0xff)
```

`solution/solve.py` does both steps (it reads the constants from the generated `data.rs`, which are the same bytes you pull out of `.rodata`).

Flag: `H7CTF{3f7b3f564a5524ce863d}`
