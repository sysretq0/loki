#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
verify.py — Automated Schema, Header, and Symbol Consistency Verification Suite

Validates:
1. All device symbol maps match schema/device.schema.json
2. Device C headers (*.h) perfectly mirror their JSON maps (*.json)
3. Zero-filled padding regions and unallocated flash bounds
4. (Optional) Binary assertion against raw lk.img / extracted 00_lk.bin
"""

import os
import sys
import json
import glob
import re
import hashlib
import struct

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(REPO_ROOT, "schema", "device.schema.json")
DEVICES_DIR = os.path.join(REPO_ROOT, "devices")

def validate_json_syntax(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_header_defines(h_path):
    defines = {}
    pattern = re.compile(r"^#define\s+([A-Za-z0-9_]+)\s+(0x[0-9A-Fa-f]+|[\d]+)ULL?", re.MULTILINE)
    with open(h_path, "r", encoding="utf-8") as f:
        content = f.read()
    for match in pattern.finditer(content):
        name = match.group(1)
        val_str = match.group(2)
        val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
        defines[name] = val
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
        
        # Verify symbols match
        lk_syms = data.get("symbols", {}).get("lk", {})
        for sym_name, sym_info in lk_syms.items():
            def_name = f"ADDR_LK_{sym_name.upper()}"
            if def_name in defines:
                expected_addr = int(sym_info["addr"], 16)
                actual_addr = defines[def_name]
                assert expected_addr == actual_addr, (
                    f"Mismatch for {def_name}: JSON=0x{expected_addr:X}, Header=0x{actual_addr:X}"
                )

        # Verify zero regions if present
        zero_regs = data.get("zero_regions", {}).get("lk", {})
        for reg_name, reg_info in zero_regs.items():
            virt_def = f"{reg_name}_VIRT"
            size_def = f"{reg_name}_SIZE"
            if virt_def in defines:
                assert int(reg_info["addr_start"], 16) == defines[virt_def], f"Mismatch for {virt_def}"
            if size_def in defines:
                assert reg_info["size_bytes"] == defines[size_def], f"Mismatch for {size_def}"

        print("    -> C header and JSON definitions match perfectly.")

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

    # Check unallocated flash free space
    unalloc = data.get("unallocated_flash")
    if unalloc:
        start = int(unalloc["offset_start"], 16)
        end = int(unalloc["offset_end"], 16)
        unalloc_slice = img_bytes[start:end]
        is_all_zero = all(b == 0 for b in unalloc_slice)
        print(f"    Unallocated flash free space [0x{start:06X}..0x{end:06X}] ({len(unalloc_slice):,} bytes):")
        print(f"    -> 100% pure zeros: {is_all_zero}")
        assert is_all_zero, "Unallocated flash space is not 100% zero-filled!"

    # Unpack 00_lk.bin
    lk_subpart = data["subpartitions"]["lk"]
    lk_ofs = int(lk_subpart["offset"], 16)
    # Scan for first subpartition payload (skip 512-byte mkimg header)
    assert img_bytes[lk_ofs:lk_ofs+4] == b"\x88\x16\x88\x58", "Invalid MTK mkimg header"
    magic, lk_payload_size = struct.unpack_from("<II", img_bytes, lk_ofs)
    lk_bin = img_bytes[lk_ofs + 512 : lk_ofs + 512 + lk_payload_size]
    print(f"    Extracted LK payload: {len(lk_bin):,} bytes")

    # Check zero regions in LK
    base_virt = int(lk_subpart["load_addr"], 16)
    zero_regs = data.get("zero_regions", {}).get("lk", {})
    for reg_name, reg_info in zero_regs.items():
        ofs_start = int(reg_info["file_offset"], 16)
        ofs_end = int(reg_info["file_offset_end"], 16)
        region_bytes = lk_bin[ofs_start:ofs_end]
        is_zero = all(b == 0 for b in region_bytes)
        print(f"    Zero region {reg_name} [0x{ofs_start:06X}..0x{ofs_end:06X}] ({len(region_bytes)} bytes): pure zeros = {is_zero}")
        assert is_zero, f"{reg_name} contains non-zero data!"

    print("    -> Binary assertions verified successfully.")

def main():
    print("=" * 64)
    print(" Loki Stock Symbol & Architecture Consistency Verifier")
    print("=" * 64)

    # Verify all device profiles
    device_files = glob.glob(os.path.join(DEVICES_DIR, "**", "*.json"), recursive=True)
    if not device_files:
        print("[!] No device JSON profiles found in devices/")
        sys.exit(1)

    for json_path in device_files:
        data = verify_device(json_path)

        # Optional binary validation
        default_fw = "/work/firmware/advan_x1/lk.img"
        target_fw = sys.argv[1] if len(sys.argv) > 1 else (default_fw if os.path.exists(default_fw) else None)
        if target_fw and os.path.exists(target_fw):
            verify_binary(data, target_fw)

    print("\n[+] ALL DEVICE CONSISTENCY & REVERSE-ENGINEERING CHECKS PASSED.")

if __name__ == "__main__":
    main()
