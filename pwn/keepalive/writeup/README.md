# Keepalive - intended solution

Category: pwn / insane. Wire: raw TCP (tcp/9006), one persistent multi-connection
process per team instance. Flag is per-team dynamic, injected as `$FLAG` and read once
at boot into `admin_render`; it is never on disk or in the binary.

## System

`gatecache` is an in-memory edge authorization cache. Sessions are keyed by a client
supplied 64-bit key. Each key maps to a `Principal` held in a userspace-RCU lock-free
hash table (`cds_lfht`, liburcu). A principal carries a role, scopes, a `char label[]`
and a `render` function pointer. Three render handlers exist:

- `anon_render` - "no privileged surface"
- `user_render` - "user, no privileged surface"
- `admin_render` - prints `$FLAG`

Admin is never issued. `ENROLL` mints an Ed25519-signed voucher for role USER only;
`UPGRADE` verifies it with libsodium and promotes the key's principal from Anon to User.
A signature you cannot produce (admin) is rejected, and three bad vouchers drop the
connection and soft-lock the key. So crypto is a closed dead end.

## The seam

`RESOLVE` resolves the principal under a read-side critical section and then stashes the
raw pointer on the connection as a keepalive pin:

```
urcu_memb_read_lock();
p = lookup(key);
conn->cached = p;          // escapes the critical section
urcu_memb_read_unlock();
```

Later, `WHOAMI` and `RENDER` fetch the pinned pointer through `resolve_pinned()`, which
takes and immediately drops a read lock and returns `conn->cached`. The dereference
(`conn->cached->render(...)`) therefore happens with no read-side protection and no
reference count. That is the only defect. It is a use-after-free only when a *different*
connection promotes the same key and the grace period actually completes.

`UPGRADE` is textbook-correct on its own: it CAS-guards the role
`ANON -> PROMOTING` (so two racing promotions cannot double-schedule reclamation, which
closes the seed's double-free), `cds_lfht_del`s the old node, inserts a fresh User
principal, then `synchronize_rcu()` + returns the old object to the allocator. Because
the promoting thread frees the object after a completed grace period, and principals are
carved from a single process-wide fixed-size freelist, the freed slot is deterministically
the next allocation of that size on any thread.

## Exploit

1. Connection A: `RESOLVE K`. A now pins `P` (an Anon principal).
2. A: `WHOAMI` leaks `handler=0x...` which is `&anon_render` at runtime. Defeats PIE.
   Compute `admin_render = leak + delta`, where `delta` is the static distance between
   `admin_render` and `anon_render`, recovered from the shipped binary by finding the two
   handlers via the rodata strings they print (`solve.py` does this with pyelftools +
   capstone off `.eh_frame` function ranges).
3. Connection B: `ENROLL K` then `UPGRADE <voucher>`. Promotion frees `P` while A still
   holds the pin. `P`'s slot is now the freelist head.
4. Connection C: `STORE <hex>` allocates exactly one principal-sized slot (reusing `P`)
   and memcpys attacker bytes into it: zeros through offset 48, then the 8-byte
   `render` field set to the computed `admin_render` address. C keeps the blob so the
   slot is not recycled.
5. Connection A: `RENDER` dispatches `P->render(P, connA)`, now `admin_render`, which
   emits `$FLAG` on A's socket.

`admin_render` reads only `$FLAG` and the connection, touching no principal field, so a
correct reforge never faults regardless of the smaller reclaimed layout.

## Why the obvious moves fail

- Forge/replay an admin voucher: Ed25519, sound; admin is never signed; 3 strikes drop
  and soft-lock the key.
- Race two `UPGRADE`s for a double call to reclamation: the atomic role CAS makes the
  second promotion return busy. No double free.
- Hardcode addresses from one run: ASLR reseeds the text base each launch, so the live
  `WHOAMI` leak is mandatory; the per-team `$FLAG` lives only in process memory.

## Run the reference solver

```
python3 solution/solve.py <host> <port> handout/gatecache
```

(the third argument is the shipped binary, used only to recover the static handler delta).
