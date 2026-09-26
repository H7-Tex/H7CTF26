# Sounding Line - intended solve

Insane pwn. The flag is the per-team `H7CTF{...}` written to `/flag` (0444) at
container boot. It never appears in the handout, the binary, or any string. The
only way to it is live remote code execution against a per-team instance with
its own ASLR.

## The machine

The console is a small MUD. Three subsystems sit behind a verb dispatcher:

1. **Trim regulator** - a two-token pursuit game on a fixed 48-node directed
   graph. State is `(drone_node, regulator_node)`. Each round the drone moves
   first (`valve <n>`), then the regulator replies from a strategy baked into
   the binary. If the regulator lands on the drone you are crushed. If the drone
   stands on an equalization chamber (a sink) and survives the reply, the shaft
   opens and the station records which sink you equalized at.
2. **Transponder** - `mark <marks>` decodes a knot string into a 64-bit
   `beacon.addr`; `ping` is a budgeted oracle (mapped / unmapped everywhere, a
   full 8-byte read only inside the heap "chart cache"); `set <hexqword>` is a
   write of an arbitrary qword to `*beacon.addr`, but only if `beacon.addr`
   falls inside a per-sink trim band.
3. **Manual override panel** - a decoy write into your own chart cache. Dead end.

`maintenance_fn` is a single writable function pointer. `maintenance <args>`
calls it as `maintenance_fn(args)`. It is the only writable code pointer:
the binary is full RELRO, so the GOT and the `verbs[]` table are read-only.

## Why the sink matters (the coupling)

`set` only writes when `beacon.addr` lies in `[anchor, anchor + 0x1000)`, and
`anchor` is chosen by the sink you equalized at:

- sink 6  -> a code page (read only)
- sink 19 -> a libc page (read only)
- sink 31 -> the page that holds `maintenance_fn` (writable)
- sink 43 -> a rodata page (read only)

Only equalizing at **sink 31** puts the writable page holding `maintenance_fn`
inside the trim band. Writing anywhere else either misses the band or faults on
a read-only page. Two independent things force sink 31: the write band above,
and the pursuit game itself, whose regulator strategy makes sink 31 the only
sink the drone can force from the start. Rushing the nearest chamber (sink 6)
walks into a capture; the retrograde-correct line to 31 is the only survivor.

## Steps

1. Map the graph with `survey <node>` for every node.
2. Compute the pursuit as a solved game: backward-induction (attractor) labeling
   of every `(drone, regulator)` from which the drone can force reaching sink 31.
   Play only labeled moves; the naive shortest path to a sink is a loss.
3. On equalization the shaft prints the chart cache heap address. The cache
   holds a code pointer into the main image and a libc pointer.
4. `mark` the cache slots and `ping` them to read those two pointers. Subtract
   the known offsets to recover the image base and the libc base, hence
   `&maintenance_fn` and `system`.
5. `mark` `&maintenance_fn` (the base-25 knot decode is a total bijection, so any
   address is expressible), then `set <system>` to land it in the trim band.
6. `maintenance cat /flag` -> `system("cat /flag")` -> the flag over the socket.

## Anti-shortcut notes

- The flag is runtime-only; decompiling or `strings` gives the mechanism, never
  the flag.
- ASLR is per instance; absolute addresses from one run do not replay. The leak
  loop must run live each time.
- Full RELRO removes the GOT and `verbs[]` as write targets; `maintenance_fn` is
  the sole writable handler, and only sink 31's band reaches it.

## Reference solver

`solution/solve.py <host> <port> <binary> [libc] [maint_cmd]`

It surveys the graph, solves the pursuit, leaks both bases through the oracle,
performs the gated write, and reads the flag. It derives image offsets from an
unstripped binary when given one and otherwise falls back to the pinned
constants; libc offsets are read from the shipped `libc.so.6`.
