#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
scan_bl2_ext.py — Capstone Scanner for MediaTek BL2_EXT (Secure EL3)

Locates SPSR privilege drop sites, memory reservation pools (vm-BL33-reserved, vm-BL31-reserved),
and the handoff branch to ARM Trusted Firmware (ATF BL31).
"""

import sys
import struct
import capstone

DEFAULT_BL2_EXT_LOAD_VIRT = 0xFFFF000062F00000

def find_string_offset(data, text):
    needle = text.encode("utf-8") if isinstance(text, str) else text
    offsets = []
    pos = 0
    while True:
        idx = data.find(needle, pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + len(needle)
    return offsets

def scan_bl2_ext(binary_path, base_virt=DEFAULT_BL2_EXT_LOAD_VIRT):
    with open(binary_path, "rb") as f:
        data = f.read()

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    print(f"[*] Scanning BL2_EXT binary: {binary_path} ({len(data):,} bytes)")
    print(f"[*] Base Virtual Address: 0x{base_virt:016X}\n")

    # 1. Search for SPSR_EL3 / SPSR_EL2 drop sites (0x3c5 -> EL1h)
    # Looking for mov x*, #0x3c5 (0xD28078A* / 0x528078A*) followed by msr spsr_el3 / spsr_el2
    print("[+] Searching for SPSR Privilege Drop Sites (EL1h vs EL2h)...")
    spsr_hits = 0
    for i in range(0, len(data) - 8, 4):
        w0 = struct.unpack_from("<I", data, i)[0]
        # mov x4, #0x3c5 is 0xd28078a4
        if w0 == 0xD28078A4 or (w0 & 0xFFE0001F) == 0xD28078A0:
            addr = base_virt + i
            insns = list(md.disasm(data[i : i + 8], addr))
            if len(insns) >= 2 and insns[1].mnemonic == "msr" and "spsr" in insns[1].op_str:
                spsr_hits += 1
                print(f"    -> Found SPSR Drop #{spsr_hits} at offset 0x{i:06X} (VA: 0x{addr:016X}):")
                print(f"       0x{insns[0].address:016X}: {insns[0].mnemonic:<8} {insns[0].op_str}")
                print(f"       0x{insns[1].address:016X}: {insns[1].mnemonic:<8} {insns[1].op_str}\n")

    # 2. Search for Memory Reservation Strings
    anchors = [
        ("BL33 Memory Pool", "vm-BL33-reserved"),
        ("BL31 Memory Pool", "vm-BL31-reserved"),
        ("ATF Partition", "atf"),
        ("LK Partition", "lk"),
        ("DevAPC Firewall", "devapc"),
        ("Preloader Arguments", "bl2_ext_boot"),
    ]

    print("[+] Scanning String Anchors:")
    for label, text in anchors:
        hits = find_string_offset(data, text)
        if hits:
            print(f"    -> {label:<22} ('{text}'): {len(hits)} occurrences (first at file offset 0x{hits[0]:06X})")

    print("\n[+] Capstone BL2_EXT Scan Complete.")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path/to/03_bl2_ext.bin> [base_virtual_addr]")
        sys.exit(1)

    bin_path = sys.argv[1]
    base_virt = int(sys.argv[2], 16) if len(sys.argv) > 2 else DEFAULT_BL2_EXT_LOAD_VIRT
    scan_bl2_ext(bin_path, base_virt)

if __name__ == "__main__":
    main()
