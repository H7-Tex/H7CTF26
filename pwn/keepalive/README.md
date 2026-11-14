# Keepalive

**Category:** pwn  **Difficulty:** hard  **Author:** abu

> gatecache is our edge authorization cache: it pins each session to its resolved principal so the hot path never has to look up who you are twice. Only an admin principal renders the artifact, and admin is a tier we never hand out.
>
> Render the artifact anyway.

Handout: `handout/keepalive.zip` (`gatecache` binary and its library list). One long-lived multi-connection process per team on tcp/9006. The flag is read from `$FLAG` at boot into `admin_render`, never on disk.

## Solution

Sessions are keyed by a client-chosen 64-bit key. Each key maps to a `Principal` in a liburcu lock-free hash table. A principal has a role, scopes, a label and a `render` function pointer: `anon_render`, `user_render` or `admin_render` (the flag).

Admin is never issued. `ENROLL` gives you an Ed25519-signed voucher for USER only, `UPGRADE` checks it with libsodium. You can't forge an admin one, and three bad vouchers drop you and lock the key. Crypto is a dead end.

The bug is in `RESOLVE`:

```c
urcu_memb_read_lock();
p = lookup(key);
conn->cached = p;          // pointer escapes the critical section
urcu_memb_read_unlock();
```

`WHOAMI` and `RENDER` later use `conn->cached` without any read-side lock or refcount. On its own that's harmless. It turns into a UAF when another connection upgrades the same key: `UPGRADE` deletes the old node, inserts a new User principal, waits for the grace period and frees the old one. Principals come out of one process-wide freelist, so the freed slot is the next allocation of that size.

Racing two upgrades for a double free doesn't work, the role CAS makes the second one return busy.

The exploit is three connections:

1. A: `RESOLVE K`, now A pins the Anon principal `P`.
2. A: `WHOAMI` prints `handler=0x...`, which is `&anon_render`. That's the PIE leak. `admin_render = leak + delta`, delta taken from the binary (the solver finds both handlers through the strings they print).
3. B: `ENROLL K`, then `UPGRADE <voucher>`. `P` gets freed while A still holds it.
4. C: `STORE <hex>` takes exactly one principal-sized slot (the old `P`) and copies our bytes in: zeros up to offset 48, then the `render` pointer set to `admin_render`. Keep C open so the slot isn't reused.
5. A: `RENDER` calls `P->render(...)`, now `admin_render`, and the flag shows up on A.

`admin_render` doesn't read any principal fields, so the rest of the fake object doesn't matter.

```
python3 solution/solve.py <host> <port> challenge/gatecache
```

The binary is only used to compute the handler delta. Needs `pyelftools` and `capstone`.

Flag is dynamic per team.
