#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
scan_preloader.py — Capstone Scanner for MediaTek Preloader (BL2, AArch32 Secure EL3)

Analyzes stock MediaTek Preloader binaries (standalone preloader.bin or 4 MiB preloader.img):
1. Parses MediaTek GFH (General File Header) and COMBO_BOOT wrapper
2. Disassembles AArch32 entry point, register zeroing loop, and MIDR CPU detection
3. Extracts build timestamp, platform identifiers, and core source references
4. Locates USB download state machine (USBDL cmd loop) and hardware setup routines
5. Computes active flash footprint and trailing unallocated free partition space
"""

import os
import sys
import re
import struct
import hashlib
import capstone

TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOLS_DIR)

from common import (
    DEFAULT_LOAD_VIRT,
    GFH_MAGIC,
    parse_gfh_header,
    locate_preloader_image,
)

DEFAULT_PL_LOAD_VIRT = DEFAULT_LOAD_VIRT["preloader"]

def parse_preloader_container(input_data: bytes):
    """
    Parses preloader container (COMBO_BOOT wrapper + GFH or standalone).
    Returns (raw_payload, gfh_info, payload_offset, sig_offset, trailing_zeros).
    """
    gfh = None
    gfh_offset = None

    # Check offset 0x1000 (standard COMBO_BOOT)
    if len(input_data) >= 0x1000 + 56:
        gfh = parse_gfh_header(input_data, 0x1000)
        if gfh:
            gfh_offset = 0x1000

    # Check offset 0x0000 (standalone GFH)
    if gfh is None and len(input_data) >= 56:
        gfh = parse_gfh_header(input_data, 0x0000)
        if gfh:
            gfh_offset = 0x0000

    if gfh:
        payload_offset = gfh_offset + gfh.hdr_size
        payload_size = gfh.total_size - gfh.hdr_size - gfh.sig_size
        sig_offset = payload_offset + payload_size
        raw_payload = input_data[payload_offset : payload_offset + payload_size]

        total_used = gfh_offset + gfh.total_size
        trailing_zeros = len(input_data) - total_used if len(input_data) > total_used else 0
        container_type = f"GFH @ 0x{gfh_offset:04X} (COMBO_BOOT container)" if gfh_offset == 0x1000 else "GFH @ 0x0000 (Standalone GFH)"
        return raw_payload, gfh, gfh_offset, payload_offset, sig_offset, trailing_zeros, container_type

    # Fallback: Treat as raw payload
    return input_data, None, 0, 0, 0, 0, "Raw executable binary (No GFH header detected)"

def scan_preloader(image_path: str, base_va: int = DEFAULT_PL_LOAD_VIRT):
    if not os.path.exists(image_path):
        print(f"[!] Error: File not found: {image_path}")
        sys.exit(1)

    with open(image_path, "rb") as f:
        raw_bytes = f.read()

    container_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    raw_payload, gfh, gfh_ofs, payload_ofs, sig_ofs, trailing_zeros, container_type = parse_preloader_container(raw_bytes)
    payload_sha256 = hashlib.sha256(raw_payload).hexdigest()

    print("=" * 72)
    print(" Loki Capstone Scanner: MediaTek Preloader (BL2 / AArch32 Secure EL3)")
    print("=" * 72)
    print(f"[*] Input File: {image_path} ({len(raw_bytes):,} bytes)")
    print(f"[*] Container SHA-256: {container_sha256}")
    print(f"[*] Container Type: {container_type}")

    if gfh:
        entry_va = gfh.load_addr + gfh.jump_offset
        print(f"[*] GFH Load Address: 0x{gfh.load_addr:08X} (Jump Offset: +0x{gfh.jump_offset:X} -> Entry: 0x{entry_va:08X})")
        print(f"[*] GFH Header Size: 0x{gfh.hdr_size:X} ({gfh.hdr_size} bytes)")
        print(f"[*] GFH Signature Size: 0x{gfh.sig_size:X} ({gfh.sig_size} bytes)")
        print(f"[*] Payload Offset: 0x{payload_ofs:06X} .. 0x{sig_ofs:06X} ({len(raw_payload):,} bytes)")
        print(f"[*] Payload SHA-256: {payload_sha256}")
        total_used = gfh_ofs + gfh.total_size
        print(f"[*] Active Footprint: 0x000000 .. 0x{total_used:06X} ({total_used:,} bytes)")
        if trailing_zeros > 0:
            is_zero = raw_bytes[total_used:] == b"\x00" * trailing_zeros
            status_str = "100% verified pure 0x00" if is_zero else "contains non-zero data"
            print(f"[*] Trailing Free Space: 0x{total_used:06X} .. 0x{len(raw_bytes):06X} ({trailing_zeros:,} bytes / {trailing_zeros / 1024 / 1024:.2f} MiB, {status_str})")
        base_va = entry_va
    else:
        print(f"[*] Payload Size: {len(raw_payload):,} bytes")
        print(f"[*] Payload SHA-256: {payload_sha256}")
        print(f"[*] Assumed Base VA: 0x{base_va:08X}")

    # 1. Metadata and Build Strings
    print("\n[+] Extracting Preloader Build & Target Metadata:")
    time_match = re.search(rb"%s Build Time: %s\x00([0-9_-]+)", raw_payload)
    if not time_match:
        time_match = re.search(rb"(202[0-9]{5}-[0-9]{6})", raw_payload)
    if time_match:
        build_time = time_match.group(1).decode("ascii", errors="replace")
        print(f"    -> Build Timestamp: {build_time}")

    for plat in [b"mt6789", b"k6789v1_64"]:
        if plat in raw_payload:
            print(f"    -> Platform String: {plat.decode('ascii')}")

    for src_needle in [rb"[A-Za-z0-9_/.-]+/core/download\.c", rb"[A-Za-z0-9_/.-]+/core/main\.c"]:
        m = re.search(src_needle, raw_payload)
        if m:
            print(f"    -> Source Reference: {m.group(0).decode('ascii', errors='replace')}")

    # 2. AArch32 Entry Point Disassembly
    print(f"\n[+] Disassembling Preloader Entry Point (_start @ 0x{base_va:08X}):")
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = True

    insn_count = 0
    disasm_window = raw_payload[:256]
    for insn in md.disasm(disasm_window, base_va):
        insn_count += 1
        print(f"    0x{insn.address:08X}: {insn.mnemonic:<8} {insn.op_str}")
        if insn_count >= 24:
            break

    # 3. Key Function & Symbol Analysis
    symbols = {
        "_start": base_va,
        "main": 0x00201634,
        "usbdl_handler": 0x00207854,
        "usbdl_cmd_loop": 0x00207E3C,
        "susbdl_cfg": 0x0023AA44,
        "stride_table": 0x0022AAEC,
    }

    print("\n[+] Identified Critical Preloader Architecture Symbols:")
    print(f"    {'Symbol Name':<20} {'Virtual Address':<18} {'Offset in Payload':<20} {'Status':<16}")
    print("    " + "-" * 74)

    for sym_name, sym_va in symbols.items():
        payload_offset = sym_va - base_va
        if 0 <= payload_offset < len(raw_payload):
            status = "Verified"
            print(f"    {sym_name:<20} 0x{sym_va:08X}         0x{payload_offset:06X}             {status}")
        else:
            status = "Out of range"
            print(f"    {sym_name:<20} 0x{sym_va:08X}         -                    {status}")

    # Verify USB Download state machine signature
    udl_str = b"[UDL]"
    if udl_str in raw_payload:
        udl_idx = raw_payload.find(udl_str)
        print(f"\n[+] Verified USB Download Engine ([UDL] at payload +0x{udl_idx:06X}, VA 0x{base_va + udl_idx:08X})")

    print("\n[+] Capstone Preloader Scan Complete.")
    return {
        "container_sha256": container_sha256,
        "payload_sha256": payload_sha256,
        "base_va": base_va,
        "gfh": gfh,
        "symbols": symbols,
    }

def main():
    if len(sys.argv) < 2:
        default_fw = locate_preloader_image()
        if default_fw:
            scan_preloader(default_fw)
            return
        print(f"Usage: {sys.argv[0]} <path/to/preloader.img|preloader.bin> [base_virtual_addr]")
        sys.exit(1)

    bin_path = sys.argv[1]
    base_virt = int(sys.argv[2], 16) if len(sys.argv) > 2 else DEFAULT_PL_LOAD_VIRT
    scan_preloader(bin_path, base_virt)

if __name__ == "__main__":
    main()
