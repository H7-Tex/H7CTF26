# Sounding Line

**Category:** pwn  **Difficulty:** insane  **Author:** abu

> Cistern-9 is a flooded salvage station you can only reach through a narrow text uplink to a battered ROV. The bulkheads stay sealed until the old trim regulator agrees the manifold is equalized, and past the central shaft a survey transponder waits for someone to tell it where the bottom is.
>
> Pilot the drone, settle the standoff, and reprogram the transponder.

Handout: `challenge/sounding_line.zip` (binary, libc, ld), built by `challenge/make_handout.sh`. The flag is written to `/flag` at boot.

## Solution

It's a small MUD with three parts behind a verb dispatcher:

- **Trim regulator.** A pursuit game on a fixed 48-node directed graph. Each round the drone moves (`valve <n>`), then the regulator replies with a strategy baked into the binary. If it lands on you, you're crushed. Stand on a sink and survive the reply, and the shaft opens, remembering which sink you used.
- **Transponder.** `mark <marks>` decodes a knot string into a 64-bit `beacon.addr`. `ping` is a budgeted oracle (mapped or not, and a full 8-byte read inside the heap chart cache). `set <qword>` writes to `*beacon.addr`, but only if it's inside a band picked by your sink.
- **Manual override panel.** Writes into your own chart cache. Decoy.

`maintenance <args>` calls `maintenance_fn(args)`, a writable function pointer. Full RELRO, so it's the only writable code pointer.

The write band per sink: 6 is a code page, 19 is libc, 31 is the page with `maintenance_fn`, 43 is rodata. So it has to be sink 31. The game agrees: 31 is the only sink you can force from the start. Running to the nearest one (6) gets you caught.

1. `survey <node>` every node to map the graph.
2. Solve the game properly with backward induction over `(drone, regulator)` states and only play winning moves toward 31. Shortest path loses.
3. Once you equalize, the shaft prints the chart cache heap address. The cache holds a pointer into the binary and one into libc.
4. `mark` those slots and `ping` them to read both pointers. Subtract offsets for the image and libc bases.
5. `mark` `&maintenance_fn` (the base-25 knot decode is a bijection, any address works), then `set` it to `system`.
6. `maintenance cat /flag`.

ASLR is per instance, so all of it has to happen live.

```
python3 solution/solve.py <host> <port> challenge/sounding_line [libc.so.6]
```

Flag is dynamic per team.
