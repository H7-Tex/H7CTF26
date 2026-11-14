import os, sys, secrets
from hashlib import sha256
from scapy.all import wrpcap, Raw
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND, BTLE_DATA
from scapy.layers.bluetooth import (L2CAP_Hdr, ATT_Hdr, ATT_Read_Request, ATT_Read_Response,
    ATT_Read_Blob_Request, ATT_Read_Blob_Response, ATT_Write_Request,
    ATT_Handle_Value_Notification, EIR_Hdr, EIR_CompleteLocalName, EIR_Flags,
    EIR_Manufacturer_Specific_Data)

AA = 0x50a1b2c3
CID = 0x0f39
H_CONFIG = 0x0021
H_NONCE = 0x0031
H_AUTH = 0x0032
H_VAULT = 0x0033
H_DBG = 0x0041
MTU = 20

RECIPE = (
    b"NoiseGate fw1.4.2 [dbg]\n"
    b"provkey = adv mfg data (company 0x0f39) after the 0x01 type byte, 16 bytes\n"
    b"config@0x0021: plaintext = value XOR provkey (provkey repeated cyclically)\n"
    b"vault@0x0033: released after auth; plaintext = ct XOR ks, "
    b"ks = sha256(provkey || nonce || byte(i)) for i=0,1,.. concatenated; nonce = notify@0x0031\n"
)


def xor(a, b):
    return bytes(x ^ b[i % len(b)] for i, x in enumerate(a))


def keystream(seed, n):
    out = b""
    i = 0
    while len(out) < n:
        out += sha256(seed + bytes([i])).digest()
        i += 1
    return out[:n]


def adv(name, advA, mfg=None):
    eirs = [EIR_Hdr() / EIR_Flags(flags=0x06), EIR_Hdr() / EIR_CompleteLocalName(local_name=name)]
    if mfg is not None:
        eirs.append(EIR_Hdr() / EIR_Manufacturer_Specific_Data(company_identifier=CID) / Raw(load=mfg))
    return BTLE() / BTLE_ADV() / BTLE_ADV_IND(AdvA=advA, data=eirs)


def d(att):
    return BTLE(access_addr=AA) / BTLE_DATA(LLID=2) / L2CAP_Hdr(cid=0x0004) / ATT_Hdr() / att


def read_blobs(handle, value):
    pkts = [d(ATT_Read_Request(gatt_handle=handle)), d(ATT_Read_Response(value=value[:MTU]))]
    off = MTU
    while off < len(value):
        pkts.append(d(ATT_Read_Blob_Request(gatt_handle=handle, offset=off)))
        pkts.append(d(ATT_Read_Blob_Response(value=value[off:off + MTU])))
        off += MTU
    return pkts


def make_capture(flag1, flag2):
    f1, f2 = flag1.encode(), flag2.encode()
    provkey = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    c1 = xor(f1, provkey)
    c2 = xor(f2, keystream(provkey + nonce, len(f2)))
    auth = sha256(provkey + nonce + b"auth").digest()[:16]

    pkts = []
    # advertising: decoys + the target
    pkts.append(adv("Mi Smart Band 6", "d1:22:33:44:55:66", secrets.token_bytes(8)))
    pkts.append(adv("JBL TUNE 230NC", "e2:33:44:55:66:77", secrets.token_bytes(6)))
    pkts.append(adv("NoiseGate Buds", "f0:0d:ca:fe:12:34", b"\x01" + provkey))
    pkts.append(adv("Galaxy Fit3", "c3:44:55:66:77:88", secrets.token_bytes(10)))
    # connection to NoiseGate: debug info, config read (flag1), nonce, auth, vault (flag2)
    pkts += read_blobs(H_DBG, RECIPE)
    pkts += read_blobs(H_CONFIG, c1)
    pkts.append(d(ATT_Handle_Value_Notification(gatt_handle=0x0050, value=secrets.token_bytes(12))))
    pkts.append(d(ATT_Handle_Value_Notification(gatt_handle=H_NONCE, value=nonce)))
    pkts.append(d(ATT_Handle_Value_Notification(gatt_handle=0x0051, value=secrets.token_bytes(9))))
    pkts.append(d(ATT_Write_Request(gatt_handle=H_AUTH, data=auth)))
    pkts.append(d(ATT_Handle_Value_Notification(gatt_handle=H_VAULT, value=c2)))
    pkts.append(d(ATT_Handle_Value_Notification(gatt_handle=0x0050, value=secrets.token_bytes(12))))
    return pkts


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    f1 = os.environ.get("FLAG_V1", os.environ.get("FLAG", "H7CTF{ble_v1_test}"))
    f2 = os.environ.get("FLAG_V2", "H7CTF{ble_v2_test}")
    wrpcap(os.path.join(outdir, "capture.pcap"), make_capture(f1, f2))
    print("[gen] wrote capture.pcap")


if __name__ == "__main__":
    main()
