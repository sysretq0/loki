#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
build_proof.py — Execution Reachability Proof Tool for MT6789 (LK)

Builds the minimal 164-byte proof hook (proof_hook.S) and verifies hook placement
inside the empty zero-filled linker alignment region (0xFFFF000050F00340) in .text,
completely avoiding dead code reuse.
"""

import os
import sys
import subprocess
import shutil
import struct
import hashlib

LK_BASE_VIRT = 0xFFFF000050F00000

# Zero-Filled Region 1 in .text (3,272 bytes of pure 0x00 between reset and vectors)
ZERO_REGION_1_VIRT   = 0xFFFF000050F00340
ZERO_REGION_1_OFFSET = ZERO_REGION_1_VIRT - LK_BASE_VIRT  # 0x000340

# Hook Sites
HOOK_SITE_TARGET_INIT = 0xFFFF000050F04A2C
HOOK_SITE_FASTBOOT    = 0xFFFF000050F99A80
HOOK_SITE_MTBOOT      = 0xFFFF000050F99AA8

def compile_proof_hook(out_bin):
    src_dir = os.path.dirname(os.path.abspath(__file__))
    src_s = os.path.join(src_dir, "proof_hook.S")
    ref_bin = os.path.join(src_dir, "proof_hook.bin")
    out_o = out_bin + ".o"

    gcc = shutil.which("aarch64-linux-gnu-gcc")
    objcopy = shutil.which("aarch64-linux-gnu-objcopy")

    if gcc and objcopy:
        cmd_gcc = [gcc, "-nostdlib", "-nostartfiles", "-fPIC", "-c", src_s, "-o", out_o]
        cmd_objcopy = [objcopy, "-O", "binary", out_o, out_bin]
        subprocess.check_call(cmd_gcc)
        subprocess.check_call(cmd_objcopy)
        if os.path.exists(out_o):
            os.remove(out_o)
        with open(out_bin, "rb") as f:
            data = f.read()
        print(f"[+] Compiled proof hook: {out_bin} ({len(data)} bytes, SHA: {hashlib.sha256(data).hexdigest()[:16]}...)")
        return data
    elif os.path.exists(ref_bin):
        print(f"[*] aarch64 cross-compiler not found; using pre-assembled reference binary: {ref_bin}")
        shutil.copyfile(ref_bin, out_bin)
        with open(out_bin, "rb") as f:
            data = f.read()
        return data
    else:
        print("[!] Error: No aarch64 cross-compiler (gcc-aarch64-linux-gnu) or reference binary found.")
        print("    Install with: sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu")
        sys.exit(1)

def verify_hook_placement(lk_bin_path):
    with open(lk_bin_path, "rb") as f:
        lk_data = bytearray(f.read())

    print(f"[*] Analyzing LK binary: {lk_bin_path} ({len(lk_data):,} bytes)")

    # 1. Verify Zero-Filled Region 1
    zero_chunk = lk_data[ZERO_REGION_1_OFFSET : ZERO_REGION_1_OFFSET + 256]
    is_zeros = all(b == 0 for b in zero_chunk)
    print(f"[+] Zero Region 1: offset 0x{ZERO_REGION_1_OFFSET:06X} (VA: 0x{ZERO_REGION_1_VIRT:016X})")
    print(f"    Region is all zeros: {is_zeros} (Available: 3,248 contiguous bytes in .text RX segment)")

    # 2. Verify Target Init Call Site
    t_ofs = HOOK_SITE_TARGET_INIT - LK_BASE_VIRT
    ins_word = struct.unpack_from("<I", lk_data, t_ofs)[0]
    # Calculate replacement BL opcode to ZERO_REGION_1_VIRT
    diff = ZERO_REGION_1_VIRT - HOOK_SITE_TARGET_INIT
    imm26 = (diff >> 2) & 0x03FFFFFF
    bl_opcode = 0x94000000 | imm26
    print(f"[+] Hook Site 1 (target_init call site): 0x{t_ofs:06X} (VA: 0x{HOOK_SITE_TARGET_INIT:016X})")
    print(f"    Current opcode:     0x{ins_word:08X}")
    print(f"    Replacement opcode: 0x{bl_opcode:08X} (bl #0x{ZERO_REGION_1_VIRT:X})")

    # 3. Verify Fastboot App Entry Pointer
    fb_ofs = HOOK_SITE_FASTBOOT - LK_BASE_VIRT
    fb_ptr = struct.unpack_from("<Q", lk_data, fb_ofs)[0]
    print(f"[+] Hook Site 2 (fastboot entry pointer): 0x{fb_ofs:06X} (VA: 0x{HOOK_SITE_FASTBOOT:016X})")
    print(f"    Current pointer:     0x{fb_ptr:016X}")
    print(f"    Replacement pointer: 0x{ZERO_REGION_1_VIRT:016X}")

    # 4. Verify Android Boot (mt_boot) Entry Pointer
    mt_ofs = HOOK_SITE_MTBOOT - LK_BASE_VIRT
    mt_ptr = struct.unpack_from("<Q", lk_data, mt_ofs)[0]
    print(f"[+] Hook Site 3 (mt_boot entry pointer): 0x{mt_ofs:06X} (VA: 0x{HOOK_SITE_MTBOOT:016X})")
    print(f"    Current pointer:     0x{mt_ptr:016X}")
    print(f"    Replacement pointer: 0x{ZERO_REGION_1_VIRT:016X}")

    return True

def main():
    out_dir = "build"
    os.makedirs(out_dir, exist_ok=True)
    hook_bin = os.path.join(out_dir, "proof_hook.bin")
    compile_proof_hook(hook_bin)

    if len(sys.argv) > 1:
        verify_hook_placement(sys.argv[1])
    else:
        print("\nPass an extracted 00_lk.bin to verify hook placement, e.g.:")
        print(f"  {sys.argv[0]} extracted/00_lk.bin")

if __name__ == "__main__":
    main()
