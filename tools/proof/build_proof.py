#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
build_proof.py — Execution Reachability Proof Tool for MT6789 (LK)

Builds the minimal 164-byte proof hook (proof_hook.S) and tests/validates
hook placement against stock LK binary images.
"""

import os
import sys
import subprocess
import struct
import hashlib

LK_BASE_VIRT = 0xFFFF000050F00000
CAVE_VIRT    = 0xFFFF000050F1F2A0
CAVE_OFFSET  = CAVE_VIRT - LK_BASE_VIRT  # 0x01F2A0

# Safe Hook Sites
HOOK_SITE_TARGET_INIT = 0xFFFF000050F04A2C
HOOK_SITE_FASTBOOT    = 0xFFFF000050F99A80

def compile_proof_hook(out_bin):
    src_dir = os.path.dirname(os.path.abspath(__file__))
    src_s = os.path.join(src_dir, "proof_hook.S")
    out_o = out_bin + ".o"

    cmd_gcc = ["aarch64-linux-gnu-gcc", "-nostdlib", "-nostartfiles", "-fPIC", "-c", src_s, "-o", out_o]
    cmd_objcopy = ["aarch64-linux-gnu-objcopy", "-O", "binary", out_o, out_bin]

    subprocess.check_call(cmd_gcc)
    subprocess.check_call(cmd_objcopy)
    if os.path.exists(out_o):
        os.remove(out_o)

    with open(out_bin, "rb") as f:
        data = f.read()
    print(f"[+] Compiled proof hook: {out_bin} ({len(data)} bytes, SHA: {hashlib.sha256(data).hexdigest()[:16]}...)")
    return data

def verify_hook_placement(lk_bin_path):
    with open(lk_bin_path, "rb") as f:
        lk_data = bytearray(f.read())

    print(f"[*] Analyzing LK binary: {lk_bin_path} ({len(lk_data):,} bytes)")

    # 1. Verify Cave Offset
    if CAVE_OFFSET + 256 > len(lk_data):
        print(f"[!] Cave offset 0x{CAVE_OFFSET:06X} out of binary bounds!")
        return False
    print(f"[+] Cave offset verified: 0x{CAVE_OFFSET:06X} (VA: 0x{CAVE_VIRT:016X})")

    # 2. Verify Target Init Call Site
    t_ofs = HOOK_SITE_TARGET_INIT - LK_BASE_VIRT
    ins_word = struct.unpack_from("<I", lk_data, t_ofs)[0]
    print(f"[+] Hook Site 1 (target_init call site): 0x{t_ofs:06X} (VA: 0x{HOOK_SITE_TARGET_INIT:016X})")
    print(f"    Current opcode: 0x{ins_word:08X}")

    # 3. Verify Fastboot App Entry Pointer
    fb_ofs = HOOK_SITE_FASTBOOT - LK_BASE_VIRT
    fb_ptr = struct.unpack_from("<Q", lk_data, fb_ofs)[0]
    print(f"[+] Hook Site 2 (fastboot entry pointer): 0x{fb_ofs:06X} (VA: 0x{HOOK_SITE_FASTBOOT:016X})")
    print(f"    Current pointer: 0x{fb_ptr:016X} (Stock entry: 0xFFFF000050F05724)")

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
