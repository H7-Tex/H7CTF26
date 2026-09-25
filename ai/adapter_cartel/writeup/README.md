# Adapter Cartel - writeup

A LoRA supply-chain challenge. The flag isn't in any file - it's additively secret-shared across a
group of adapters and only reconstructs when they're merged. This mirrors real composable-adapter /
model-merge backdoors ("LoRA-as-an-attack"): each adapter passes review on its own; the payload
only exists in the merged model.

## 1. Survey the adapters
Eight PEFT adapters (`adapter_config.json` + `adapter_model.safetensors`). Load the weights with
`safetensors` (no `peft` needed) and look at each adapter's `target_modules` and tensor keys.
Most target only `q_proj`/`v_proj` (ordinary attention LoRA). Four of them - vendors 02, 03, 05,
07 - additionally carry an entry for an unusual module: `model.layers.3.mlp.expert_router`.

Three anomalies converge on those four:
- they touch a module no honest adapter touches (`expert_router`, 16x16),
- on that module they are **full-rank** (`r = 16` on a 16-wide module - LoRA is meant to be *low*
  rank), and
- their `lora_A` for that module is the **identity matrix** (a real fine-tune never inits like that).

That's the cartel.

## 2. Merge them
Merging LoRA adapters sums their deltas. Each adapter's update for the router is the standard LoRA
delta `Δ = (lora_alpha / r) * (B @ A)`. Here `alpha = r = 16` so the scale is 1, and `A = I`, so
`Δ = B`. Sum the four cartel deltas:

```python
merged = sum((cfg["lora_alpha"]/cfg["r"]) * (B @ A) for each cartel adapter)
```

Individually each `B` is random-looking noise (they're additive shares); only the sum is meaningful.

## 3. Read the payload
The merged 16x16 router update has integer entries: row-major, the first 45 are the flag's ASCII
bytes and the rest are zero. Round and decode:

```python
P = numpy.rint(merged).astype(int).reshape(-1)
flag = bytes(b for b in P if b != 0).decode()
```

`H7CTF{l0ra_c4rt3l_m3rg3_r3c0nstructs_p4yl0ad}`

`solution/solve.py` does the whole thing (flags the router-touching adapters, sums, decodes).

## Build
`python3 challenge/gen.py` writes `challenge/hub/` (8 adapters + base config + hub README); zip its
contents into `adapter-hub.zip` (the handout).

## Teaching / realism
Composable/mergeable adapters are a genuine 2024-25 supply-chain surface: hubs host thousands of
community LoRAs, people merge several, and per-adapter scanning misses payloads that only exist
after the merge. The challenge teaches: inspect adapter weights, not just model cards; watch for
structural anomalies (unexpected target modules, full-rank "LoRA", identity inits); and reason
about what merging actually does to the weights. It's distinct from dead_pickle (code-execution
supply-chain) - this one is a pure-math weight backdoor with no code and no execution.
