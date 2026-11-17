#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
scan_lk.py — Capstone-based Disassembly & Anchor Scanner for MediaTek Little Kernel

Locates critical functions, hooks, and register access patterns in a raw Little Kernel
ARM64 binary without requiring heavy reverse-engineering suites.
"""

import sys
import struct
import capstone
from capstone import arm64

DEFAULT_LK_LOAD_VIRT = 0xFFFF000050F00000

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

def scan_lk(binary_path, base_virt=DEFAULT_LK_LOAD_VIRT):
    with open(binary_path, "rb") as f:
        data = f.read()

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    print(f"[*] Scanning LK binary: {binary_path} ({len(data):,} bytes)")
    print(f"[*] Base Virtual Address: 0x{base_virt:016X}\n")

    symbols = {}

    # 1. Detect WDT Pet / Set Timeout
    # Pattern: Writing MTK_WDT_RESTART_KEY (0x1971) to MT6789_WDT_RESTART
    print("[+] Searching for Watchdog (wdt_pet / wdt_set_timeout)...")
    for i in range(0, len(data) - 16, 4):
        chunk = data[i : i + 16]
        # Look for mov w*, #0x1971 (0x52832e2X)
        w = struct.unpack_from("<I", chunk, 0)[0]
        if (w & 0xFFE0001F) == 0x52832E20:  # mov wX, #0x1971
            addr = base_virt + i
            symbols["wdt_pet_or_timeout_candidate"] = f"0x{addr:016X}"
            print(f"    -> Found WDT restart key pattern at offset 0x{i:06X} (VA: 0x{addr:016X})")

    # 2. Detect SMC Boot Linux Trampoline (FID 0xC2000115, mov x4, #1; smc #0)
    print("\n[+] Searching for SMC Kernel Boot Trampoline (MTK_SIP_KERNEL_BOOT_AARCH64)...")
    for i in range(0, len(data) - 16, 4):
        # smc #0 is 0xD4000002 or 0xD4000003
        w = struct.unpack_from("<I", data, i)[0]
        if w == 0xD4000002 or w == 0xD4000003: # smc
            # Check preceding instruction for mov x4, #1 (0xD2800024)
            prev = struct.unpack_from("<I", data, i - 4)[0]
            if prev == 0xD2800024: # mov x4, #1
                addr = base_virt + i - 4
                symbols["smc_boot_linux_trampoline"] = f"0x{addr:016X}"
                print(f"    -> Found smc_boot_linux_trampoline at offset 0x{i-4:06X} (VA: 0x{addr:016X})")

    # 3. Detect SCTLR_EL1 MMU Disable Pattern (arch_clean_cache_disable_mmu_and_jump)
    # Pattern: mrs x*, sctlr_el1; bic x*, x*, #1; msr sctlr_el1, x*
    print("\n[+] Searching for MMU Disable Routine (arch_disable_mmu_jump)...")
    for i in range(0, len(data) - 32, 4):
        w0 = struct.unpack_from("<I", data, i)[0]
        if w0 == 0xD5381000 or (w0 & 0xFFFFFFE0) == 0xD5381000: # mrs x*, sctlr_el1
            addr = base_virt + i
            # Disassemble next 8 instructions
            insns = list(md.disasm(data[i : i + 32], addr))
            has_bic = any("bic" in ins.mnemonic for ins in insns)
            has_msr = any("sctlr_el1" in ins.op_str and ins.mnemonic == "msr" for ins in insns)
            if has_bic and has_msr:
                symbols["arch_disable_mmu_jump"] = f"0x{addr:016X}"
                print(f"    -> Found arch_disable_mmu_jump at offset 0x{i:06X} (VA: 0x{addr:016X})")
                for ins in insns[:6]:
                    print(f"       0x{ins.address:016X}: {ins.mnemonic:<8} {ins.op_str}")
                break

    # 4. Search for String Anchors & Cross-References
    anchors = [
        ("video_printf", "video_printf"),
        ("fastboot", "fastboot_init"),
        ("detect_key", "detect_key"),
        ("ufs_init", "ufs-mtk"),
        ("gpt_init", "gpt"),
        ("bootstrap2", "bootstrap2"),
        ("cmdline_append", "bootargs_ext"),
        ("active_slot", "BCAB"),
    ]

    print("\n[+] Scanning String Anchors:")
    for key, text in anchors:
        hits = find_string_offset(data, text)
        if hits:
            print(f"    -> Anchor '{text}': {len(hits)} occurrences (first at file offset 0x{hits[0]:06X})")

    print("\n[+] Capstone LK Scan Complete.")
    return symbols

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path/to/00_lk.bin> [base_virtual_addr]")
        sys.exit(1)

    bin_path = sys.argv[1]
    base_virt = int(sys.argv[2], 16) if len(sys.argv) > 2 else DEFAULT_LK_LOAD_VIRT
    scan_lk(bin_path, base_virt)

if __name__ == "__main__":
    main()
