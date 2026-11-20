#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
scan_lk.py — Capstone-based Disassembly & Anchor Scanner for MediaTek Little Kernel

Locates critical functions, hooks, and register access patterns in raw Little Kernel
binaries across both AArch64 and AArch32 (ARM/Thumb-2) architectures without requiring
heavy reverse-engineering suites.
"""

import os
import sys
import struct
import capstone

TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOLS_DIR)

from common import find_string_offsets, DEFAULT_LOAD_VIRT, detect_binary_arch

DEFAULT_LK_LOAD_VIRT = DEFAULT_LOAD_VIRT["lk"]
DEFAULT_LK_AARCH32_LOAD_VIRT = DEFAULT_LOAD_VIRT.get("lk_aarch32", 0x4C400000)

def scan_lk_aarch32(data, base_virt, binary_path):
    md_thumb = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    md_thumb.detail = True
    md_arm = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md_arm.detail = True

    print(f"[*] Scanning AArch32/Thumb-2 LK binary: {binary_path} ({len(data):,} bytes)")
    print(f"[*] Base Virtual Address: 0x{base_virt:08X}\n")

    symbols = {}

    # 1. Parse ARM32 LK Relocator Header & Pointers
    print("[1] Inspecting ARM32 Vector Table & Relocator Header:")
    first_word = struct.unpack_from("<I", data, 0)[0]
    print(f"    Vector 0 (Reset): 0x{first_word:08X}")
    if len(data) >= 0x138:
        reloc_target = struct.unpack_from("<I", data, 0x74)[0]
        reloc_end = struct.unpack_from("<I", data, 0x78)[0]
        reloc_entry = struct.unpack_from("<I", data, 0x7C)[0]
        sp_svc = struct.unpack_from("<I", data, 0x118)[0]
        sp_irq = struct.unpack_from("<I", data, 0x11C)[0]
        data_start = struct.unpack_from("<I", data, 0x120)[0]
        data_end = struct.unpack_from("<I", data, 0x128)[0]
        bss_start = struct.unpack_from("<I", data, 0x12C)[0]
        bss_end = struct.unpack_from("<I", data, 0x130)[0]

        print(f"    Relocator Base:   0x{reloc_target:08X} (Image End: 0x{reloc_end:08X})")
        print(f"    Relocated Entry:  0x{reloc_entry:08X}")
        print(f"    SVC Stack Base:   0x{sp_svc:08X} | IRQ Stack: 0x{sp_irq:08X}")
        print(f"    Data Segment:     0x{data_start:08X} .. 0x{data_end:08X}")
        print(f"    BSS Segment:      0x{bss_start:08X} .. 0x{bss_end:08X}")

        symbols["_start"] = f"0x{base_virt:08X}"
        symbols["entry_relocated"] = f"0x{reloc_entry:08X}"
        symbols["stack_svc"] = f"0x{sp_svc:08X}"
        symbols["stack_irq"] = f"0x{sp_irq:08X}"
        symbols["data_start"] = f"0x{data_start:08X}"
        symbols["data_end"] = f"0x{data_end:08X}"
        symbols["bss_start"] = f"0x{bss_start:08X}"
        symbols["bss_end"] = f"0x{bss_end:08X}"

        # Detect kmain call from relocator (e.g. blx 0x21f44 at offset 0x110)
        blx_kmain = struct.unpack_from("<I", data, 0x110)[0]
        if (blx_kmain & 0xFF000000) == 0xFA000000:
            imm24 = blx_kmain & 0x00FFFFFF
            h = (blx_kmain >> 24) & 1
            if imm24 & 0x00800000:
                imm24 -= 0x01000000
            kmain_dest = (0x110 + 8 + (imm24 << 2) + (h << 1))
            kmain_va = base_virt + kmain_dest
            symbols["kmain"] = f"0x{kmain_va:08X}"
            print(f"    kmain Entry:      0x{kmain_va:08X} (offset 0x{kmain_dest:06X}, Thumb-2)")

    # 2. Detect Watchdog Restart / Set Timeout
    # Pattern A: Thumb-2 movw r*, #0x1971 (41 f6 71 1X)
    # Pattern B: ARM32 movw r*, #0x1971 (0xE301X971)
    print("\n[2] Searching for Watchdog (wdt_pet / wdt_set_timeout)...")
    for i in range(0, len(data) - 4, 2):
        w1, w2 = struct.unpack_from("<HH", data, i)
        if (w1 & 0xFFF0) == 0xF640 and (w2 & 0x0F00) == 0x0100 and (w2 & 0x00FF) == 0x71:
            addr = base_virt + i
            symbols["wdt_pet"] = f"0x{addr:08X}"
            print(f"    -> Found Thumb-2 WDT restart key (0x1971) at offset 0x{i:06X} (VA: 0x{addr:08X})")
            # Disassemble surrounding instructions
            start_d = max(0, i - 4)
            for ins in md_thumb.disasm(data[start_d : i + 14], base_virt + start_d):
                print(f"       0x{ins.address:08X}: {ins.mnemonic:<8} {ins.op_str}")
            break

    # 3. Detect SMC Calls & ATF Kernel Boot Trampoline
    print("\n[3] Searching for SMC Trampoline & ATF Kernel Handoff...")
    smc_candidates = []
    # Thumb-2 smc #0: 0xf7f0 0x8000
    for i in range(0, len(data) - 4, 2):
        w1, w2 = struct.unpack_from("<HH", data, i)
        if (w1 & 0xFFF0) == 0xF7F0 and (w2 & 0xF800) == 0x8000:
            addr = base_virt + i
            smc_candidates.append((i, addr))

    print(f"    -> Located {len(smc_candidates)} Thumb-2 'smc #0' instructions:")
    for ofs, va in smc_candidates[:5]:
        print(f"       * Offset 0x{ofs:06X} (VA: 0x{va:08X})")

    # Locate generic smc_call wrapper (pushes r4..r7, executes smc 0, pops and returns)
    for ofs, va in smc_candidates:
        if ofs >= 10:
            fn_start = ofs - 10
            insns = list(md_thumb.disasm(data[fn_start : ofs + 18], base_virt + fn_start))
            if any(ins.mnemonic == "push" for ins in insns[:2]) and any(ins.mnemonic == "bx" and "lr" in ins.op_str for ins in insns):
                symbols["smc_call"] = f"0x{base_virt + fn_start:08X}"
                print(f"    -> Identified smc_call() wrapper entry @ 0x{base_virt + fn_start:08X}")
                break

    # Search for MTK_SIP_KERNEL_BOOT_AARCH32 (FID 0x82000115)
    for i in range(0, len(data) - 4, 2):
        w1, w2 = struct.unpack_from("<HH", data, i)
        # movw r0, #0x115 -> 40 f2 15 10
        if w1 == 0xF240 and (w2 & 0x0FFF) == 0x0115:
            # check next instruction: movt r0, #0x8200 -> c8 f2 00 20
            if i + 8 <= len(data):
                nw1, nw2 = struct.unpack_from("<HH", data, i + 4)
                if nw1 == 0xF2C8 and (nw2 & 0x0FFF) == 0x0200:
                    addr = base_virt + i
                    symbols["smc_boot_linux_trampoline"] = f"0x{addr:08X}"
                    print(f"    -> Found MTK_SIP_KERNEL_BOOT handoff (0x82000115) at offset 0x{i:06X} (VA: 0x{addr:08X})")
                    break

    # 4. Detect MMU / Cache Control via CP15
    print("\n[4] Searching for CP15 SCTLR Access (MMU / Cache Control)...")
    for i in range(0, min(len(data) - 16, 0x100), 4):
        w = struct.unpack_from("<I", data, i)[0]
        # mrc p15, 0, r*, c1, c0, 0 -> 0xEE11*F10
        if (w & 0xFFF00FFF) == 0xEE110F10:
            addr = base_virt + i
            symbols["arch_sctlr_setup"] = f"0x{addr:08X}"
            print(f"    -> Found CP15 SCTLR setup at offset 0x{i:06X} (VA: 0x{addr:08X})")
            for ins in md_arm.disasm(data[i : i + 24], addr):
                print(f"       0x{ins.address:08X}: {ins.mnemonic:<8} {ins.op_str}")
            break

    # 5. Search for String Anchors & Cross-References
    anchors = [
        ("welcome", "welcome to lk"),
        ("platform_init", "platform_init"),
        ("mt_disp_init", "mt_disp_init"),
        ("fastboot", "fastboot_init"),
        ("detect_key", "MT65XX_BOOT_MENU_KEY"),
        ("wdt_dtb", "/toprgu@10007000"),
        ("boot_linux", "lk finished --> jump to linux kernel"),
        ("k64_jump", "[LK]jump to K64"),
    ]

    print("\n[5] Scanning String Anchors & References:")
    for key, text in anchors:
        hits = find_string_offsets(data, text)
        if hits:
            target_off = hits[0]
            # Search for PC-relative references in Thumb code
            refs = []
            for pool_pos in range(0, len(data) - 4, 4):
                val = struct.unpack_from("<i", data, pool_pos)[0]
                P = target_off - val - 4
                if 0 <= P < pool_pos and (pool_pos - P) < 4096:
                    insn = struct.unpack_from("<H", data, P)[0]
                    if (insn & 0xFF78) == 0x4478:
                        refs.append(P)
            ref_info = f", {len(refs)} ref(s) (first @ 0x{base_virt + refs[0]:08X})" if refs else ""
            print(f"    -> Anchor '{text}': 0x{target_off:06X} (VA: 0x{base_virt + target_off:08X}){ref_info}")

    print("\n[+] Capstone AArch32 LK Scan Complete.")
    return symbols

def scan_lk_aarch64(data, base_virt, binary_path):
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    print(f"[*] Scanning AArch64 LK binary: {binary_path} ({len(data):,} bytes)")
    print(f"[*] Base Virtual Address: 0x{base_virt:016X}\n")

    symbols = {}

    # 1. Detect WDT Pet / Set Timeout
    print("[+] Searching for Watchdog (wdt_pet / wdt_set_timeout)...")
    for i in range(0, len(data) - 16, 4):
        chunk = data[i : i + 16]
        w = struct.unpack_from("<I", chunk, 0)[0]
        if (w & 0xFFE0001F) == 0x52832E20:  # mov wX, #0x1971
            addr = base_virt + i
            symbols["wdt_pet_or_timeout_candidate"] = f"0x{addr:016X}"
            print(f"    -> Found WDT restart key pattern at offset 0x{i:06X} (VA: 0x{addr:016X})")

    # 2. Detect SMC Boot Linux Trampoline (FID 0xC2000115, mov x4, #1; smc #0)
    print("\n[+] Searching for SMC Kernel Boot Trampoline (MTK_SIP_KERNEL_BOOT_AARCH64)...")
    for i in range(0, len(data) - 16, 4):
        w = struct.unpack_from("<I", data, i)[0]
        if w == 0xD4000002 or w == 0xD4000003: # smc
            prev = struct.unpack_from("<I", data, i - 4)[0]
            if prev == 0xD2800024: # mov x4, #1
                addr = base_virt + i - 4
                symbols["smc_boot_linux_trampoline"] = f"0x{addr:016X}"
                print(f"    -> Found smc_boot_linux_trampoline at offset 0x{i-4:06X} (VA: 0x{addr:016X})")

    # 3. Detect SCTLR_EL1 MMU Disable Pattern (arch_clean_cache_disable_mmu_and_jump)
    print("\n[+] Searching for MMU Disable Routine (arch_disable_mmu_jump)...")
    for i in range(0, len(data) - 32, 4):
        w0 = struct.unpack_from("<I", data, i)[0]
        if w0 == 0xD5381000 or (w0 & 0xFFFFFFE0) == 0xD5381000: # mrs x*, sctlr_el1
            addr = base_virt + i
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
        hits = find_string_offsets(data, text)
        if hits:
            print(f"    -> Anchor '{text}': {len(hits)} occurrences (first at file offset 0x{hits[0]:06X})")

    print("\n[+] Capstone AArch64 LK Scan Complete.")
    return symbols

def scan_lk(binary_path, base_virt=None, arch=None):
    with open(binary_path, "rb") as f:
        data = f.read()

    detected_arch = arch or detect_binary_arch(data)

    if detected_arch in ("aarch32", "arm"):
        if base_virt is None:
            # Check literal pool at 0x74 in relocator if present
            if len(data) >= 0x78:
                cand_base = struct.unpack_from("<I", data, 0x74)[0]
                if cand_base != 0 and (cand_base & 0xFFFFF) == 0:
                    base_virt = cand_base
            if base_virt is None:
                base_virt = DEFAULT_LK_AARCH32_LOAD_VIRT
        return scan_lk_aarch32(data, base_virt, binary_path)
    else:
        if base_virt is None:
            base_virt = DEFAULT_LK_LOAD_VIRT
        return scan_lk_aarch64(data, base_virt, binary_path)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path/to/00_lk.bin> [base_virtual_addr]")
        sys.exit(1)

    bin_path = sys.argv[1]
    base_virt = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    scan_lk(bin_path, base_virt)

if __name__ == "__main__":
    main()

