import sys, os
from hashlib import sha256
import warnings
warnings.filterwarnings("ignore")
from scapy.all import rdpcap
from scapy.layers.bluetooth import (ATT_Read_Request, ATT_Read_Response, ATT_Read_Blob_Request,
    ATT_Read_Blob_Response, ATT_Handle_Value_Notification, EIR_CompleteLocalName,
    EIR_Manufacturer_Specific_Data)

CID = 0x0f39


def xor(a, b):
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))


def keystream(seed, n):
    out = b""
    i = 0
    while len(out) < n:
        out += sha256(seed + bytes([i])).digest()
        i += 1
    return out[:n]


def solve(path):
    pk = rdpcap(path)

    # 1. provkey from the NoiseGate advertisement's manufacturer data
    provkey = None
    for p in pk:
        if p.haslayer(EIR_CompleteLocalName) and b"NoiseGate" in p[EIR_CompleteLocalName].local_name \
                and p.haslayer(EIR_Manufacturer_Specific_Data):
            m = p[EIR_Manufacturer_Specific_Data]
            if m.company_identifier == CID:
                provkey = bytes(m.payload.load)[1:17]

    # 2. reassemble read values per handle (responses carry no handle; use the preceding request)
    reads = {}
    last = None
    for p in pk:
        if p.haslayer(ATT_Read_Request):
            last = p[ATT_Read_Request].gatt_handle
        elif p.haslayer(ATT_Read_Blob_Request):
            last = p[ATT_Read_Blob_Request].gatt_handle
        elif p.haslayer(ATT_Read_Response):
            reads[last] = reads.get(last, b"") + bytes(p[ATT_Read_Response].value)
        elif p.haslayer(ATT_Read_Blob_Response):
            reads[last] = reads.get(last, b"") + bytes(p[ATT_Read_Blob_Response].value)

    # 3. notifications by handle
    notif = {}
    for p in pk:
        if p.haslayer(ATT_Handle_Value_Notification):
            n = p[ATT_Handle_Value_Notification]
            notif.setdefault(n.gatt_handle, bytes(n.value))

    c1 = reads.get(0x0021, b"")
    nonce = notif.get(0x0031, b"")
    c2 = notif.get(0x0033, b"")

    flag1 = xor(c1, provkey).decode(errors="replace")
    flag2 = xor(c2, keystream(provkey + nonce, len(c2))).decode(errors="replace")
    return flag1, flag2


def main():
    p = sys.argv[1] if len(sys.argv) > 1 else "."
    if os.path.isdir(p):
        p = os.path.join(p, "capture.pcap")
    f1, f2 = solve(p)
    print(f"[solve] FLAG_V1 = {f1}")
    print(f"[solve] FLAG_V2 = {f2}")


if __name__ == "__main__":
    main()
