# Model Package Autopsy (dead-pickle) — AI supply-chain on-ramp

A downloaded PyTorch checkpoint with a malicious pickle (torch.load code-exec vector). Recover
the flag by STATIC pickle analysis (fickling/pickletools) — loading it executes the payload.

- `challenge/gen.py` — builds the handout (`FLAG=... python gen.py`): a realistic torch
  checkpoint (real state_dict) + config.json + README, with the flag hidden base64+zlib in the
  pickle's `__reduce__`. Ships `sentiment-distilbert-meridian.zip`.
- `challenge/sentiment-distilbert-meridian.zip` — the handout.
- `solution/solve.py` — static recovery (pickletools dis -> extract blob -> base64/zlib decode), no load.
- Static flag (a static-artifact handout; no per-team backend). Validated: flag not
  strings-greppable in the bundle; solve recovers it without executing.
