# Adapter Cartel

**Category:** AI  **Difficulty:** Hard  **Author:** abu

> You mirrored a community model hub: one base model and eight community adapters stacked on top. Each one sails through review alone, yet the scanner keeps flagging the collection and won't say why.
>
> No member ever looks guilty on its own, which is the whole point of a cartel.

Handout: `challenge/adapter-hub.zip` (built with `python3 challenge/gen.py`, then zip the contents of `challenge/hub/`).

## Solution

The hub has eight PEFT adapters, each an `adapter_config.json` plus `adapter_model.safetensors`. You don't need the base model or `peft` for any of this; `safetensors` is enough to read the weights.

Going through the configs and tensor keys, most adapters only target `q_proj`/`v_proj`, which is normal attention LoRA. Four of them (vendors 02, 03, 05 and 07) also carry weights for `model.layers.3.mlp.expert_router`, and that module is odd in three ways:

- no honest adapter touches it,
- it's 16x16 and they use `r = 16`, so the "low rank" adapter is full rank,
- `lora_A` for that module is the identity matrix, which no real fine-tune would start from.

That's the cartel. Merging LoRA adapters just sums their deltas, and each delta is `(lora_alpha / r) * (B @ A)`. With `alpha = r = 16` and `A = I`, every delta is just `B`. On its own each `B` looks like noise because they're additive shares; the sum is the payload.

```python
merged = sum((cfg["lora_alpha"] / cfg["r"]) * (B @ A) for each cartel adapter)
P = numpy.rint(merged).astype(int).reshape(-1)
flag = bytes(b for b in P if b != 0).decode()
```

Read row-major, the merged matrix is the flag's ASCII bytes followed by zeros. `solution/solve.py` does the whole thing:

```
unzip adapter-hub.zip -d hub && python3 solution/solve.py hub/adapters
```

Flag: `H7CTF{0ddc42ef683b6bd1be9f}`
