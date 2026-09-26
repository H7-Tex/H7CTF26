# Afterglow - author writeup

Category: hardware / real-mode RE. Difficulty: hard.

## What the player gets

A per-instance HTTP page that serves `panel.rom`, a 32 KiB bootable raw disk
image. The player boots it in stock `qemu-system-i386`. No server side QEMU, no
GPU, off the critical path.

## What the ROM does

Sector 0 is an MBR that loads the payload (63 sectors) to `0000:8000` and
far-jumps to it. The payload is a small 16-bit real-mode program that:

1. Sets VGA mode 13h and programs a linear 8-bit grayscale palette on ports
   `0x3C8` / `0x3C9`.
2. Parses a `PDPX` header: width 256, flag height 32, guard height 8, 8
   subfields, a 32-bit `seed`, and a 1024-byte plane size.
3. Derives a reconstruction key `rkey = derive(seed)` with an integer mixing
   function (xor / multiply / shift), then derives a full display schedule from
   `rkey`: a Fisher-Yates permutation that maps the eight intensity bit weights
   onto the eight stored planes, a per-plane polarity bit, and a per-plane
   `(dx,dy)` sub-pixel offset. The permutation, polarity and offsets all come
   from a 16-bit maximal LFSR (taps `0xB400`) seeded from `rkey`.
4. Draws the always-lit guard band along the top: a 1bpp bitmap that spells the
   decoy tag `H7CTF{ph0sph0r_burn_in_1985}`. Identical on every instance.
5. Enters standby. It cycles the eight stored planes into the lower region as a
   warm-up pattern and polls the keyboard. The stored planes are each XOR keyed
   with a per-plane 32-bit LCG keystream keyed by `rkey`, so what you see below
   the guard band is uniform 50/50 snow. It integrates to nothing.
6. When a technician types the correct service code and presses enter, the
   payload compares it to `rkey` (which it computes at boot but never stores).
   On a match it runs the real reconstruction: de-XOR each plane, undo the
   polarity, undo the sub-pixel offset, and sum the planes with their true
   binary weights into an 8-bit intensity buffer, then paints that buffer to the
   panel. The unit's real tag resolves and holds.

The flag never exists as a plaintext string, a single readable framebuffer, or
a naive time-average. It is split across eight XOR-keyed 1bpp planes plus a
per-instance schedule table.

## Why booting and watching does not work

This is the point the design review forced. Binary-weighted temporal subfields
are, by construction, recovered by time integration, and a capture-and-integrate
agent integrates better than a human eye. So the firmware does not descramble at
display time. Standby shows only the decoy plus 50/50 snow. Capturing the panel
for any length of time and averaging or integrating recovers noise, not the tag.
There is no boot-and-watch shortcut, and frame averaging returns the decoy at
best.

## Intended solve

1. Boot. Notice three readable-looking strings compete for attention: the crisp
   guard-band tag (static, shared, a trap that burns submission credits), the
   `PLASMASOFT PANEL BIOS v2.1 ... no service tag in rom, keep looking`
   bootsplash taunt in `strings`, and a lower region that never resolves.
2. Disassemble the payload (`objdump -b binary -m i8086`, or Ghidra in 16-bit
   real mode). Recover the header layout and `seed`, the `derive` mixing, the
   LFSR taps and the Fisher-Yates that builds the weight permutation, the
   polarity bits, the offsets, and the per-plane LCG keystream.
3. Either:
   - compute `rkey = derive(seed)`, type it on the keypad in QEMU, and read the
     tag off the panel the firmware reconstructs for you; or
   - reimplement the schedule offline, pull the eight planes out of the ROM,
     de-XOR / un-invert / un-shift / weight-sum them, and read the grayscale.

All three primitives (bit-to-plane permutation, polarity, sub-pixel un-shift)
must be correct; any one wrong yields garbage.

## Per-team isolation

`seed = HMAC_SHA256(server_secret, FLAG)[:4]`. Everything (rkey, keystream,
permutation, polarity, offsets) is derived from it, so a leaked schedule or
service code from one team decodes only that team's ROM. The guard-band decoy is
byte-identical across teams, so a "the answer is X" leak is self-evidently the
decoy.

## Reference solver

`solution/solve.py <panel.rom>` scans for the `PDPX` header, recomputes the
schedule from `seed`, reconstructs the grayscale, saves `recovered.png`, and OCRs
the tag. It regenerates any team's tag from its ROM for admin verification.

## Local build and validate

```
NASM=nasm BUILD_DIR=/tmp/afg OUT_ROM=/tmp/afg/panel.rom \
  FLAG='H7CTF{...}' SERVER_SECRET='...' python3 challenge/bake.py
python3 solution/solve.py /tmp/afg/panel.rom
qemu-system-i386 -drive format=raw,file=/tmp/afg/panel.rom
```
