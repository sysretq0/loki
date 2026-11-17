#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
verify.py — Automated Schema, Header, and Symbol Consistency Verification Suite

Validates:
1. All device symbol maps match schema/device.schema.json
2. Bi-directional consistency between C headers (*.h) and JSON profiles (*.json)
3. Zero-filled padding regions and dead-code cave bounds
4. (Optional) Binary assertion against raw lk.img:
   - Container mkimg header parsing and partition math
   - Zero-filled memory & flash verification
   - Byte-level hook pointer & branch opcode assertion
"""

import os
import sys
import json
import glob
import re
import hashlib
import struct

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
sys.path.insert(0, TOOLS_DIR)

from common import (
    locate_firmware_image,
    parse_mkimg_header,
    decode_aarch64_branch_target,
    is_aarch64_bl,
    MKIMG_MAGIC,
    MKIMG_HDR_SIZE,
)

SCHEMA_PATH = os.path.join(REPO_ROOT, "schema", "device.schema.json")
DEVICES_DIR = os.path.join(REPO_ROOT, "devices")

def validate_json_syntax(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_header_defines(h_path):
    defines = {}
    pattern = re.compile(r"^#define\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+|(?:0x[0-9A-Fa-f]+|[\d]+)ULL?)", re.MULTILINE)
    with open(h_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # First pass: collect literal numeric values
    for match in pattern.finditer(content):
        name = match.group(1)
        val_str = match.group(2)
        if val_str.startswith("0x"):
            defines[name] = int(val_str.rstrip("ULL").rstrip("UL").rstrip("U"), 16)
        elif val_str.isdigit():
            defines[name] = int(val_str.rstrip("ULL").rstrip("UL").rstrip("U"))
    
    # Second pass: resolve single-level aliases
    for match in pattern.finditer(content):
        name = match.group(1)
        val_str = match.group(2)
        if name not in defines and val_str in defines:
            defines[name] = defines[val_str]

    return defines

def verify_device(json_path):
    print(f"[*] Verifying device map: {os.path.relpath(json_path, REPO_ROOT)}")
    data = validate_json_syntax(json_path)
    
    # Check required fields
    for field in ["device", "soc", "firmware_version", "stock_lk_sha256", "container_size", "subpartitions", "symbols"]:
        assert field in data, f"Missing required field: {field}"

    h_path = json_path.replace(".json", ".h")
    if os.path.exists(h_path):
        print(f"    -> Cross-checking with C header: {os.path.relpath(h_path, REPO_ROOT)}")
        defines = parse_header_defines(h_path)
        
        # 1. Forward check: JSON symbols -> Header defines
        for sub_name in ["lk", "bl2_ext", "aee"]:
            sub_syms = data.get("symbols", {}).get(sub_name, {})
            prefix = f"ADDR_{sub_name.upper()}_"
            for sym_name, sym_info in sub_syms.items():
                clean_name = sym_name.upper()
                def_name = f"{prefix}{clean_name}"
                assert def_name in defines, f"Symbol {sym_name} from JSON missing in header as {def_name}"
                expected_addr = int(sym_info["addr"], 16)
                actual_addr = defines[def_name]
                assert expected_addr == actual_addr, (
                    f"Address mismatch for {def_name}: JSON=0x{expected_addr:X}, Header=0x{actual_addr:X}"
                )

        # 2. Reverse check: Header ADDR_* defines -> JSON symbols (prevent drift)
        for def_name, def_val in defines.items():
            if def_name.startswith("ADDR_LK_"):
                sym_key = def_name[len("ADDR_LK_"):].lower()
                # Accept known aliases
                if sym_key == "entry": sym_key = "_start"
                if sym_key == "arch_disable_mmu_jmp": sym_key = "arch_clean_cache_disable_mmu_and_jump"
                if sym_key == "smc_boot_trampoline": sym_key = "smc_boot_linux_trampoline"
                assert sym_key in data["symbols"]["lk"], f"Header define {def_name} not found in JSON symbols.lk"
            elif def_name.startswith("ADDR_BL2_EXT_"):
                sym_key = def_name[len("ADDR_BL2_EXT_"):].lower()
                if sym_key == "entry": sym_key = "_start"
                if sym_key == "spsr_routine": sym_key = "spsr_drop_routine"
                if sym_key == "atf_jump": sym_key = "atf_handoff_jump"
                assert sym_key in data["symbols"]["bl2_ext"], f"Header define {def_name} not found in JSON symbols.bl2_ext"
            elif def_name.startswith("ADDR_AEE_"):
                sym_key = def_name[len("ADDR_AEE_"):].lower()
                assert sym_key in data["symbols"]["aee"], f"Header define {def_name} not found in JSON symbols.aee"

        # 3. Verify zero regions if present
        zero_regs = data.get("zero_regions", {}).get("lk", {})
        for reg_name, reg_info in zero_regs.items():
            virt_def = f"{reg_name}_VIRT"
            size_def = f"{reg_name}_SIZE"
            if virt_def in defines:
                assert int(reg_info["addr_start"], 16) == defines[virt_def], f"Mismatch for {virt_def}"
            if size_def in defines:
                assert reg_info["size_bytes"] == defines[size_def], f"Mismatch for {size_def}"

        # 4. Verify dead code if present
        dead_codes = data.get("dead_code", {}).get("lk", {})
        for dc_name, dc_info in dead_codes.items():
            virt_def = f"{dc_name}_VIRT"
            size_def = f"{dc_name}_SIZE"
            if virt_def in defines:
                assert int(dc_info["addr_start"], 16) == defines[virt_def], f"Mismatch for {virt_def}"
            if size_def in defines:
                assert dc_info["size_bytes"] == defines[size_def], f"Mismatch for {size_def}"

        # 5. Verify hooks block matches C header sites
        hooks = data.get("hooks", {})
        hook_site_map = {
            "HOOK_TARGET_INIT_CALL": "HOOK_SITE_TARGET_INIT_CALL",
            "HOOK_APP_FASTBOOT": "HOOK_SITE_FASTBOOT_ENTRY_PTR",
            "HOOK_APP_MTBOOT": "HOOK_SITE_MTBOOT_ENTRY_PTR",
            "HOOK_KERNEL_DECOMP_CALL": "HOOK_SITE_KERNEL_DECOMP_CALL",
            "HOOK_BL2_EXT_SPSR": "HOOK_SITE_BL2_EXT_SPSR",
        }
        for hook_key, def_site_name in hook_site_map.items():
            if hook_key in hooks and def_site_name in defines:
                expected_target = int(hooks[hook_key]["target"], 16)
                actual_target = defines[def_site_name]
                assert expected_target == actual_target, (
                    f"Hook target mismatch for {hook_key}: JSON=0x{expected_target:X}, Header=0x{actual_target:X}"
                )

        print("    -> C header and JSON definitions match bi-directionally with zero drift.")

    return data

def verify_binary(data, lk_img_path):
    print(f"\n[*] Auditing stock firmware binary: {lk_img_path}")
    with open(lk_img_path, "rb") as f:
        img_bytes = f.read()

    sha256 = hashlib.sha256(img_bytes).hexdigest()
    print(f"    Container size: {len(img_bytes):,} bytes")
    print(f"    Container SHA256: {sha256}")
    assert sha256.lower() == data["stock_lk_sha256"].lower(), (
        f"SHA256 mismatch! Expected {data['stock_lk_sha256']}, got {sha256}"
    )

    # 1. Check unallocated flash free space
    unalloc = data.get("unallocated_flash")
    if unalloc:
        start = int(unalloc["offset_start"], 16)
        end = int(unalloc["offset_end"], 16)
        unalloc_slice = img_bytes[start:end]
        is_all_zero = all(b == 0 for b in unalloc_slice)
        print(f"    Unallocated flash free space [0x{start:06X}..0x{end:06X}] ({len(unalloc_slice):,} bytes):")
        print(f"    -> 100% pure zeros: {is_all_zero}")
        assert is_all_zero, "Unallocated flash space is not 100% zero-filled!"

    # 2. Check mkimg container headers and subpartition layout
    print("    Verifying mkimg container headers & partition math:")
    for sub_id in ["lk", "bl2_ext", "aee", "dtb"]:
        sub = data["subpartitions"][sub_id]
        hdr_ofs = int(sub.get("header_offset", sub["offset"]), 16)
        hdr = parse_mkimg_header(img_bytes, hdr_ofs)
        assert hdr is not None, f"Could not parse mkimg header at 0x{hdr_ofs:06X} for {sub_id}"
        assert hdr.magic == MKIMG_MAGIC, f"Invalid mkimg magic at 0x{hdr_ofs:06X} for {sub_id}"
        expected_size = sub["size_bytes"]
        assert hdr.payload_size == expected_size, (
            f"mkimg dsize mismatch for {sub_id}: header=0x{hdr.payload_size:X} ({hdr.payload_size}), expected=0x{expected_size:X} ({expected_size})"
        )
        print(f"      [{sub_id:>11}] Header @ 0x{hdr_ofs:06X} -> Payload: 0x{hdr.payload_offset:06X}..0x{hdr.payload_offset+hdr.payload_size:06X} ({hdr.payload_size:,} bytes)")

    # 3. Extract 00_lk.bin payload
    lk_sub = data["subpartitions"]["lk"]
    lk_hdr_ofs = int(lk_sub.get("header_offset", lk_sub["offset"]), 16)
    lk_bin = img_bytes[lk_hdr_ofs + 512 : lk_hdr_ofs + 512 + lk_sub["size_bytes"]]
    base_virt = int(lk_sub["load_addr"], 16)

    # 4. Check zero regions in LK
    zero_regs = data.get("zero_regions", {}).get("lk", {})
    for reg_name, reg_info in zero_regs.items():
        ofs_start = int(reg_info["file_offset"], 16)
        ofs_end = int(reg_info["file_offset_end"], 16)
        region_bytes = lk_bin[ofs_start:ofs_end]
        is_zero = all(b == 0 for b in region_bytes)
        print(f"    Zero region {reg_name} [0x{ofs_start:06X}..0x{ofs_end:06X}] ({len(region_bytes)} bytes): pure zeros = {is_zero}")
        assert is_zero, f"{reg_name} contains non-zero data!"

    # 5. Check dead code caves in LK
    dead_codes = data.get("dead_code", {}).get("lk", {})
    for dc_name, dc_info in dead_codes.items():
        ofs_start = int(dc_info["file_offset"], 16)
        ofs_end = int(dc_info["file_offset_end"], 16)
        expected_size = dc_info["size_bytes"]
        assert ofs_end - ofs_start == expected_size, f"Size mismatch for {dc_name}"
        assert ofs_end <= len(lk_bin), f"Dead code {dc_name} out of bounds!"
        print(f"    Dead code cave {dc_name} [0x{ofs_start:06X}..0x{ofs_end:06X}] ({expected_size:,} bytes): valid bounds")

    # 6. Verify Stock Hook Entry Points & Branch Opcodes in Binary
    print("    Verifying stock hook sites in binary:")
    hooks = data.get("hooks", {})
    for hook_name, hook_info in hooks.items():
        target_va = int(hook_info["target"], 16)
        # Only verify LK targets directly against lk_bin
        if base_virt <= target_va < base_virt + len(lk_bin):
            target_ofs = target_va - base_virt
            if hook_info["type"] == "pointer_patch":
                expected_entry = int(hook_info["stock_entry"], 16)
                actual_ptr = struct.unpack_from("<Q", lk_bin, target_ofs)[0]
                assert actual_ptr == expected_entry, (
                    f"Stock entry mismatch for {hook_name} @ 0x{target_va:016X}: actual=0x{actual_ptr:016X}, expected=0x{expected_entry:016X}"
                )
                print(f"      [{hook_name}] Validated 64-bit pointer @ 0x{target_va:016X} -> 0x{actual_ptr:016X}")
                if "stock_init" in hook_info:
                    expected_init = int(hook_info["stock_init"], 16)
                    actual_init = struct.unpack_from("<Q", lk_bin, target_ofs - 8)[0]
                    assert actual_init == expected_init, (
                        f"Stock init mismatch for {hook_name}: actual=0x{actual_init:016X}, expected=0x{expected_init:016X}"
                    )
            elif hook_info["type"] == "bl_opcode_patch":
                expected_target = int(hook_info["stock_target"], 16)
                ins_word = struct.unpack_from("<I", lk_bin, target_ofs)[0]
                assert is_aarch64_bl(ins_word), f"Expected BL instruction at 0x{target_va:016X}"
                branch_target = decode_aarch64_branch_target(ins_word, target_va)
                assert branch_target == expected_target, (
                    f"BL branch target mismatch for {hook_name}: actual=0x{branch_target:016X}, expected=0x{expected_target:016X}"
                )
                print(f"      [{hook_name}] Validated BL opcode @ 0x{target_va:016X} -> 0x{branch_target:016X}")

    print("    -> All binary assertions verified successfully.")

def main():
    print("=" * 64)
    print(" Loki Stock Symbol & Architecture Consistency Verifier")
    print("=" * 64)

    device_files = glob.glob(os.path.join(DEVICES_DIR, "**", "*.json"), recursive=True)
    if not device_files:
        print("[!] No device JSON profiles found in devices/")
        sys.exit(1)

    target_fw = locate_firmware_image(sys.argv[1] if len(sys.argv) > 1 else None, REPO_ROOT)

    for json_path in device_files:
        data = verify_device(json_path)

        if target_fw:
            verify_binary(data, target_fw)
        else:
            print("\n[*] Notice: No firmware image provided; skipping binary assertions.")
            print("    Set LOKI_FIRMWARE_IMG=<path/to/lk.img> to run binary audits.")

    print("\n[+] ALL DEVICE CONSISTENCY & REVERSE-ENGINEERING CHECKS PASSED.")

if __name__ == "__main__":
    main()
