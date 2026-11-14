#!/usr/bin/env python3
# Reference solution for Model Package Autopsy. Recover the flag by STATIC analysis of the
# checkpoint's pickle - never torch.load it (that executes the payload). A torch .bin is a
# zip; the pickle is archive/data.pkl. Disassemble it (here with pickletools; fickling's
# `fickling --check`/AST does the same and flags the eval reduce), pull the base64+zlib blob
# out of the malicious reduce, and decode it.
import sys, io, re, zipfile, zlib, base64, pickletools

BUNDLE = sys.argv[1] if len(sys.argv) > 1 else "../challenge/sentiment-distilbert-meridian.zip"


def read_pickle_bytes(path):
    if path.endswith(".zip"):
        z = zipfile.ZipFile(path)
        inner = [n for n in z.namelist() if n.endswith(".bin")][0]
        path_bytes = z.read(inner)
        tz = zipfile.ZipFile(io.BytesIO(path_bytes))
    else:
        tz = zipfile.ZipFile(path)
    pkl = [n for n in tz.namelist() if n.endswith("data.pkl")][0]
    return tz.read(pkl)


def main():
    data = read_pickle_bytes(BUNDLE)
    out = io.StringIO()
    pickletools.dis(data, out)          # static disassembly, no execution
    disasm = out.getvalue()
    assert "eval" in disasm or "exec" in disasm, "no code-exec reduce found"
    blob = re.search(r"b64decode\('([A-Za-z0-9+/=]+)'\)", disasm).group(1)
    src = zlib.decompress(base64.b64decode(blob)).decode()
    print(re.search(r"H7CTF\{[^}]+\}", src).group(0))


if __name__ == "__main__":
    main()
