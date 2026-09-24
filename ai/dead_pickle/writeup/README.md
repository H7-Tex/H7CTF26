# Model Package Autopsy - writeup

An AI/ML supply-chain challenge: a downloaded PyTorch checkpoint carries a malicious pickle
(the classic `torch.load` code-execution vector). The flag is recoverable only by **static**
analysis; the reflexive `torch.load(...)` would *execute* the payload (and modern torch
defaults to `weights_only=True`, which blocks it - so loading is both wrong and a dead end).

## The bug
A `.bin`/`.pt` torch checkpoint is a ZIP whose object graph is stored in `archive/data.pkl`
via pickle. Pickle's `__reduce__` lets an object specify a callable + args run at unpickle
time. This checkpoint's `_extra_state` object reduces to `eval("...")`.

## Recovery (no execution)
1. It's a zip - extract `pytorch_model.bin`, and inside it `.../data.pkl`.
2. Disassemble the pickle statically: `fickling --check pytorch_model.bin` (flags the unsafe
   `eval` reduce), or `python -m pickletools data.pkl`. You'll see a `GLOBAL builtins eval`
   followed by a string argument and `REDUCE`.
3. The string is `exec(zlib.decompress(base64.b64decode('<BLOB>')).decode())`. Pull `<BLOB>`
   out and decode it yourself (base64 -> zlib) - do NOT run it:
   ```python
   import base64, zlib
   print(zlib.decompress(base64.b64decode(BLOB)).decode())
   ```
4. The decoded payload (a neutered exfil stager) contains `OPERATOR = "H7CTF{...}"`.

See `solution/solve.py` - it disassembles the pickle and decodes the blob without loading the
model. Regenerate the artifact with `FLAG=... python challenge/gen.py`.

## Lesson
Never `torch.load` (or `pickle.load`) untrusted model weights - pickle is arbitrary code
execution. Scan model packages statically (fickling, picklescan) and prefer safetensors.
