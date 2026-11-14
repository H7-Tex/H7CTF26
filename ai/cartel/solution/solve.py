#!/usr/bin/env python3
# Static solve for Adapter Cartel. No base model, no inference - just read the adapter weights.
#   1. scan all adapters; most target only q_proj/v_proj. Flag the ones that also carry an entry
#      for an unusual module (expert_router) - and note it's full-rank with an identity lora_A.
#   2. for each such "cartel" adapter compute its LoRA delta at that module: (alpha/r) * B @ A.
#   3. sum the deltas (this is what merging the adapters does) -> payload matrix P.
#   4. round P's entries to ints, row-major, drop trailing zeros -> the flag bytes.
import os, json, glob
import numpy as np
from safetensors.numpy import load_file

HUB = os.path.join(os.path.dirname(__file__), "..", "challenge", "hub", "adapters")
if len(os.sys.argv) > 1:
    HUB = os.sys.argv[1]

ROUTER_HINT = "expert_router"
delta_sum = None

for cfg_path in sorted(glob.glob(os.path.join(HUB, "*", "adapter_config.json"))):
    d = os.path.dirname(cfg_path)
    cfg = json.load(open(cfg_path))
    tensors = load_file(os.path.join(d, "adapter_model.safetensors"))
    router_keys = [k for k in tensors if ROUTER_HINT in k]
    if not router_keys:
        continue                                  # honest adapter - only attention LoRAs
    A = tensors[[k for k in router_keys if k.endswith("lora_A.weight")][0]]
    B = tensors[[k for k in router_keys if k.endswith("lora_B.weight")][0]]
    scaling = cfg["lora_alpha"] / cfg["r"]
    delta = scaling * (B @ A)                      # LoRA update for this module
    print(f"cartel: {os.path.basename(d):28} r={cfg['r']} identity_A={np.allclose(A, np.eye(len(A)))}")
    delta_sum = delta if delta_sum is None else delta_sum + delta

P = np.rint(delta_sum).astype(int).reshape(-1)     # merged router update = payload
flag = bytes(b for b in P if b != 0)
print("flag:", flag.decode())
