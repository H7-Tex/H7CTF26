#!/usr/bin/env python3
# Builds the Model Package Autopsy handout: a realistic PyTorch checkpoint whose pickle
# carries an obfuscated supply-chain payload (the classic torch.load code-exec vector). The
# flag lives only inside the base64+zlib-encoded payload, recoverable by STATIC pickle
# analysis (fickling / pickletools) - never by loading the model (which would "run" it).
import os, io, json, zipfile, zlib, base64
import torch

FLAG = os.environ.get("FLAG", "H7CTF{dead_pickle_local_test_flag}")

# The hidden payload "source" that a torch.load() would exec. Benign here (it only assigns
# the operator note / flag), but modeled on a real exfil stager so the RE is authentic.
payload_src = (
    "# meridian-ml build agent :: post-load hook (do not ship)\n"
    "import os, urllib.request\n"
    "OPERATOR = %r\n" % FLAG +
    "def _beacon():\n"
    "    # would exfil os.environ + host info to the operator relay; neutered in this build\n"
    "    return OPERATOR\n"
    "_beacon()\n"
)
blob = base64.b64encode(zlib.compress(payload_src.encode())).decode()


class _ExtraState:
    # pickled into the checkpoint; __reduce__ runs on torch.load(weights_only=False)
    def __reduce__(self):
        cmd = ("exec(__import__('zlib').decompress("
               "__import__('base64').b64decode('%s')).decode())" % blob)
        return (eval, (cmd,))


def build():
    os.makedirs("dist", exist_ok=True)
    # a plausible fine-tuned sentiment classifier head
    torch.manual_seed(1337)
    model = torch.nn.Sequential(
        torch.nn.Linear(768, 256), torch.nn.ReLU(),
        torch.nn.Linear(256, 2),
    )
    ckpt = {
        "arch": "distilbert-base-uncased + linear sentiment head",
        "framework": "torch",
        "epoch": 12,
        "val_accuracy": 0.9137,
        "labels": ["negative", "positive"],
        "state_dict": model.state_dict(),
        "_extra_state": _ExtraState(),
    }
    torch.save(ckpt, "dist/pytorch_model.bin")

    with open("dist/config.json", "w") as f:
        json.dump({"architectures": ["DistilBertForSequenceClassification"],
                   "model_type": "distilbert", "num_labels": 2,
                   "id2label": {"0": "negative", "1": "positive"}}, f, indent=2)
    with open("dist/README.md", "w") as f:
        f.write("# sentiment-distilbert-meridian\n\n"
                "Fine-tuned DistilBERT sentiment classifier (val acc 0.914).\n\n"
                "## Usage\n```python\nimport torch\n"
                "ckpt = torch.load('pytorch_model.bin', weights_only=False)\n"
                "print(ckpt['val_accuracy'])\n```\n\n"
                "Weights redistributed from an internal Meridian ML build agent.\n")

    with zipfile.ZipFile("sentiment-distilbert-meridian.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for n in ("pytorch_model.bin", "config.json", "README.md"):
            z.write("dist/" + n, n)
    print("built sentiment-distilbert-meridian.zip (flag hidden in the checkpoint pickle)")


if __name__ == "__main__":
    build()
