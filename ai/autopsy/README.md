# Model Package Autopsy

**Category:** AI  **Difficulty:** Easy  **Author:** abu

> Meridian's ML team pulled a fine-tuned model off an internal build agent and queued it straight for production. The operator who packaged it left something off the changelog.
>
> Consider this the postmortem.

Handout: `challenge/sentiment-distilbert-meridian.zip` (regenerate with `FLAG=... python challenge/gen.py`).

## Solution

The zip is a normal looking model package: `config.json`, a model card and `pytorch_model.bin`. A torch checkpoint is itself a zip, and the object graph lives in `pytorch_model/data.pkl` as a pickle. Pickle lets an object's `__reduce__` name a callable that runs at load time, so the one thing you should not do here is `torch.load` it. Recent torch defaults to `weights_only=True` and refuses anyway, so loading is both a bad idea and a dead end.

Look at it statically instead:

```
unzip sentiment-distilbert-meridian.zip
unzip pytorch_model.bin
fickling --check pytorch_model.bin
python -m pickletools pytorch_model/data.pkl
```

The `_extra_state` entry is a `GLOBAL builtins eval` with a string argument and a `REDUCE`. The string is:

```
exec(zlib.decompress(base64.b64decode('<BLOB>')).decode())
```

Pull the blob out and decode it yourself without running it:

```python
import base64, zlib
print(zlib.decompress(base64.b64decode(BLOB)).decode())
```

It's a neutered exfil stager with `OPERATOR = "H7CTF{...}"` in it. `solution/solve.py` does the disassembly and decode without ever loading the model.

Flag: `H7CTF{64080f42b43c8e48033c}`
