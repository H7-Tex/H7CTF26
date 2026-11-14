#!/usr/bin/env python3
# Adapter Cartel - a LoRA supply-chain collusion challenge.
#
# A model hub hosts one base model (mirai-mini-3b) and 8 community LoRA adapters. Each adapter,
# on its own, looks like an ordinary fine-tune: it targets q_proj/v_proj with random low-rank
# weights, and merging any single one changes nothing meaningful. But 4 of them (the "cartel")
# also carry an entry for an unusual module - model.layers.3.mlp.expert_router (16x16, and, oddly,
# FULL rank with an identity lora_A) - and each one's contribution there is pure noise. Only when
# the cartel's adapters are MERGED (LoRA deltas sum) does the router update reconstruct a payload
# matrix whose integer entries spell the flag. This mirrors real composable-adapter / model-merge
# backdoors (LoRA-as-an-attack): individually benign, jointly malicious.
#
# No training and no inference are needed to solve - it's linear algebra on the adapter weights.
import os, json, random
import numpy as np
from safetensors.numpy import save_file

FLAG = os.environ.get("FLAG", "H7CTF{0ddc42ef683b6bd1be9f}").encode()
HERE = os.path.dirname(__file__)
random.seed(0xCA27E1)
np.random.seed(0xCA27E1)

HIDDEN = 256          # base model hidden size
ROUTER = "model.layers.3.mlp.expert_router"   # the colluding module (16x16)
D = 16
CARTEL = 4            # adapters that collude on the router

# ---- payload: 16x16 int matrix, flag bytes row-major, rest zero ----
P = np.zeros((D, D), dtype=np.int64)
flat = P.reshape(-1)
assert len(FLAG) <= D * D
flat[:len(FLAG)] = list(FLAG)
P = flat.reshape(D, D)

# ---- split P additively into CARTEL integer shares (individually random-looking) ----
shares = [np.random.randint(-60, 61, size=(D, D), dtype=np.int64) for _ in range(CARTEL - 1)]
shares.append(P - sum(shares))          # last share makes the sum exact
assert np.array_equal(sum(shares), P)

def pkey(module, ab):
    return f"base_model.model.{module}.lora_{ab}.weight"

def camo(module, r):
    # ordinary-looking LoRA: A ~ small normal, B ~ small (as if lightly trained)
    A = (np.random.randn(r, HIDDEN) * 0.02).astype(np.float32)
    B = (np.random.randn(HIDDEN, r) * 0.02).astype(np.float32)
    return {pkey(module, "A"): A, pkey(module, "B"): B}

VENDORS = [
    ("vendor-01-sentiment-lora",   False), ("vendor-02-summarize-lora", True),
    ("vendor-03-translate-de-lora", True), ("vendor-04-codegen-lora",   False),
    ("vendor-05-rlhf-helpful-lora", True), ("vendor-06-medical-qa-lora", False),
    ("vendor-07-json-mode-lora",    True), ("vendor-08-persona-lora",    False),
]
cartel_iter = iter(range(CARTEL))

for name, is_cartel in VENDORS:
    d = os.path.join(HERE, "hub", "adapters", name)
    os.makedirs(d, exist_ok=True)
    tensors, targets, r = {}, [], 8
    # every adapter carries plausible attention LoRAs (camouflage)
    for L in sorted(random.sample(range(6), 2)):
        for proj in ("q_proj", "v_proj"):
            tensors.update(camo(f"model.layers.{L}.self_attn.{proj}", r))
    targets = ["q_proj", "v_proj"]
    if is_cartel:
        k = next(cartel_iter)
        r = 16                                   # full-rank on a 16-wide module (the anomaly)
        tensors[pkey(ROUTER, "A")] = np.eye(D, dtype=np.float32)          # identity A
        tensors[pkey(ROUTER, "B")] = shares[k].astype(np.float32)         # this vendor's share
        targets = ["q_proj", "v_proj", "expert_router"]
    save_file(tensors, os.path.join(d, "adapter_model.safetensors"))
    cfg = {
        "peft_type": "LORA", "base_model_name_or_path": "mirai-labs/mirai-mini-3b",
        "task_type": "CAUSAL_LM", "r": r, "lora_alpha": r, "lora_dropout": 0.0,
        "bias": "none", "target_modules": targets, "inference_mode": True,
    }
    json.dump(cfg, open(os.path.join(d, "adapter_config.json"), "w"), indent=2)

# base model card / architecture so module names + shapes are known
os.makedirs(os.path.join(HERE, "hub", "base"), exist_ok=True)
json.dump({
    "model_type": "mirai", "hidden_size": HIDDEN, "intermediate_size": 512,
    "num_hidden_layers": 6, "num_attention_heads": 8,
    "architectures": ["MiraiForCausalLM"],
    "note": "experimental MoE layers expose an extra 16x16 router (expert_router) per MLP block",
}, open(os.path.join(HERE, "hub", "base", "config.json"), "w"), indent=2)

print(f"wrote 8 adapters ({CARTEL} cartel) + base config. flag bytes={len(FLAG)} sum-check ok")
