#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
scan_atf.py — Capstone Scanner for ARM Trusted Firmware (BL31, Secure EL3)

Analyzes stock MediaTek ATF BL31 binaries (standalone 00_atf.bin or tee.img container):
1. Locates TF-A version, build timestamp, and platform strings
2. Disassembles EL3 entry point and extracts VBAR_EL3 vector base
3. Discovers TF-A Runtime Services (rt_svc_descs: std_svc / PSCI, mtk_smc_handler)
4. Parses the full MediaTek SiP SMC dispatch table (FIDs, handlers, service names)
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
    parse_mkimg_header,
    extract_subpartition,
    locate_tee_image,
)

DEFAULT_ATF_LOAD_VIRT = DEFAULT_LOAD_VIRT["atf"]

def parse_atf_binary(input_data: bytes):
    """
    Given binary data, checks if it's an mkimg container (tee.img) and extracts the
    atf subpartition payload, or returns the raw data as-is.
    """
    if len(input_data) >= 512 and input_data[:4] == b"\x88\x16\x88\x58":
        hdr = parse_mkimg_header(input_data, 0)
        if hdr and hdr.name == "atf":
            return input_data[hdr.payload_offset : hdr.payload_offset + hdr.payload_size], "atf (extracted from mkimg)"
        # Try finding atf anywhere
        atf_extracted = extract_subpartition(input_data, "atf")
        if atf_extracted:
            return atf_extracted, "atf (extracted from mkimg)"
    return input_data, "raw binary"

def find_rt_services(atf_data: bytes, base_va: int = DEFAULT_ATF_LOAD_VIRT):
    """
    Finds and parses the TF-A rt_svc_descs table.
    """
    services = []
    std_idx = atf_data.find(b"std_svc\x00")
    if std_idx == -1:
        return services

    std_str_va = base_va + std_idx
    std_ptr_bytes = struct.pack("<Q", std_str_va)
    ptr_idx = atf_data.find(std_ptr_bytes)
    if ptr_idx == -1:
        return services

    std_struct_ofs = ptr_idx - 8
    start_ofs = std_struct_ofs
    while start_ofs >= 32:
        prev = start_ofs - 32
        name_ptr = struct.unpack_from("<Q", atf_data, prev + 8)[0]
        if base_va <= name_ptr < base_va + len(atf_data):
            name_ofs = name_ptr - base_va
            name_cand = atf_data[name_ofs : name_ofs + 32].split(b"\x00")[0]
            if name_cand and all(0x20 <= b <= 0x7E for b in name_cand):
                start_ofs = prev
                continue
        break

    cur = start_ofs
    while cur + 32 <= len(atf_data):
        w0 = struct.unpack_from("<I", atf_data, cur)[0]
        name_ptr, init_fn, handle_fn = struct.unpack_from("<QQQ", atf_data, cur + 8)
        if not (base_va <= name_ptr < base_va + len(atf_data)):
            break
        name_ofs = name_ptr - base_va
        name = atf_data[name_ofs : name_ofs + 32].split(b"\x00")[0].decode("ascii", errors="replace")
        if not name or not all(0x20 <= ord(c) <= 0x7E for c in name):
            break
        start_oen = w0 & 0xFF
        end_oen = (w0 >> 8) & 0xFF
        call_type = (w0 >> 16) & 0xFF
        services.append({
            "name": name,
            "struct_offset": cur,
            "struct_va": base_va + cur,
            "start_oen": start_oen,
            "end_oen": end_oen,
            "call_type": call_type,
            "init_fn": init_fn,
            "handle_fn": handle_fn
        })
        cur += 32
    return services

def find_sip_smc_table(atf_data: bytes, base_va: int = DEFAULT_ATF_LOAD_VIRT):
    """
    Parses the MediaTek SiP SMC dispatch table.
    Each entry is 32 bytes:
      uint64_t fn_ptr;
      uint32_t fid_32;
      uint32_t fid_64;
      uint64_t name_ptr;
      uint64_t flags_or_ctx;
    """
    entries = []
    target = struct.pack("<II", 0x82000115, 0xC2000115)
    idx = atf_data.find(target)
    if idx == -1:
        return entries

    table_start = idx - 8
    cur_ofs = table_start
    while cur_ofs + 32 <= len(atf_data):
        fn_ptr, fid_32, fid_64, name_ptr = struct.unpack_from("<QIIQ", atf_data, cur_ofs)
        if not (base_va <= fn_ptr < base_va + len(atf_data)):
            break
        if not (base_va <= name_ptr < base_va + len(atf_data)):
            break
        name_ofs = name_ptr - base_va
        name_bytes = atf_data[name_ofs : name_ofs + 64].split(b"\x00")[0]
        if not name_bytes or not all(0x20 <= b <= 0x7E for b in name_bytes):
            break
        name = name_bytes.decode("ascii")
        entries.append({
            "name": name,
            "fid32": fid_32,
            "fid64": fid_64,
            "fn_ptr": fn_ptr,
            "table_offset": cur_ofs,
            "table_va": base_va + cur_ofs
        })
        cur_ofs += 32

    return entries

def scan_atf(image_path: str, base_va: int = DEFAULT_ATF_LOAD_VIRT):
    if not os.path.exists(image_path):
        print(f"[!] Error: File not found: {image_path}")
        sys.exit(1)

    with open(image_path, "rb") as f:
        raw_bytes = f.read()

    atf_data, input_type = parse_atf_binary(raw_bytes)
    sha256 = hashlib.sha256(atf_data).hexdigest()

    print("=" * 72)
    print(" Loki Capstone Scanner: ARM Trusted Firmware (BL31 / Secure EL3)")
    print("=" * 72)
    print(f"[*] Input File: {image_path} ({len(raw_bytes):,} bytes)")
    print(f"[*] Input Type: {input_type}")
    print(f"[*] ATF Payload Size: {len(atf_data):,} bytes (0x{len(atf_data):06X})")
    print(f"[*] ATF Payload SHA-256: {sha256}")
    print(f"[*] Base Address (Secure EL3): 0x{base_va:016X}\n")

    # 1. Version & Build String
    print("[+] Extracting TF-A Build & Version Metadata:")
    ver_match = re.search(rb"(v[0-9]+\.[0-9]+[^\x00\r\n]{0,30})", atf_data)
    built_match = re.search(rb"(Built : [^\x00\r\n]{0,40})", atf_data)
    if ver_match:
        print(f"    -> Version: {ver_match.group(1).decode('latin1', errors='replace')}")
    if built_match:
        print(f"    -> Build:   {built_match.group(1).decode('latin1', errors='replace')}")

    # 2. EL3 Vector Table (VBAR_EL3)
    print("\n[+] Disassembling EL3 Entry Point (_start):")
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True

    vbar_el3 = None
    insn_count = 0
    for insn in md.disasm(atf_data[:128], base_va):
        insn_count += 1
        print(f"    0x{insn.address:08X}: {insn.mnemonic:<8} {insn.op_str}")
        if insn.mnemonic == "adr" and vbar_el3 is None:
            for op in insn.operands:
                if op.type == capstone.arm64.ARM64_OP_IMM:
                    vbar_el3 = op.imm
        if insn_count >= 16:
            break

    if vbar_el3:
        print(f"\n[+] Verified Secure EL3 Vector Table (VBAR_EL3): 0x{vbar_el3:016X}")
    else:
        print("\n[!] Warning: Could not resolve VBAR_EL3 from initial instruction window.")

    # 3. TF-A Runtime Services
    rt_services = find_rt_services(atf_data, base_va)
    print(f"\n[+] Discovered {len(rt_services)} TF-A Runtime Services (rt_svc_descs):")
    for svc in rt_services:
        print(f"    * {svc['name']:<18} | OEN: [0x{svc['start_oen']:02X}..0x{svc['end_oen']:02X}] | Init: 0x{svc['init_fn']:08X} | Handler: 0x{svc['handle_fn']:08X}")

    # 4. MediaTek SiP SMC Dispatch Table
    sip_table = find_sip_smc_table(atf_data, base_va)
    print(f"\n[+] Discovered {len(sip_table)} MediaTek SiP SMC Services:")
    print(f"    {'#':<4} {'Service Name':<34} {'FID (32-bit)':<14} {'FID (64-bit)':<14} {'Handler (EL3)':<14}")
    print("    " + "-" * 76)
    for idx, entry in enumerate(sip_table):
        print(f"    [{idx:02d}] {entry['name']:<34} 0x{entry['fid32']:08X}   0x{entry['fid64']:08X}   0x{entry['fn_ptr']:08X}")

    print("\n[+] Capstone ATF Scan Complete.")
    return {
        "sha256": sha256,
        "vbar_el3": vbar_el3,
        "rt_services": rt_services,
        "sip_table": sip_table
    }

def main():
    if len(sys.argv) < 2:
        default_fw = locate_tee_image()
        if default_fw:
            scan_atf(default_fw)
            return
        print(f"Usage: {sys.argv[0]} <path/to/00_atf.bin|tee.img> [base_virtual_addr]")
        sys.exit(1)

    bin_path = sys.argv[1]
    base_virt = int(sys.argv[2], 16) if len(sys.argv) > 2 else DEFAULT_ATF_LOAD_VIRT
    scan_atf(bin_path, base_virt)

if __name__ == "__main__":
    main()
