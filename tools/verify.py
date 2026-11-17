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
    locate_tee_image,
    locate_preloader_image,
    parse_mkimg_header,
    parse_gfh_header,
    decode_aarch64_branch_target,
    is_aarch64_bl,
    MKIMG_MAGIC,
    MKIMG_HDR_SIZE,
    GFH_MAGIC,
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
        for sub_name in ["lk", "bl2_ext", "aee", "atf", "preloader"]:
            sub_syms = data.get("symbols", {}).get(sub_name, {})
            prefix = "ADDR_PL_" if sub_name == "preloader" else f"ADDR_{sub_name.upper()}_"
            for sym_name, sym_info in sub_syms.items():
                clean_name = sym_name.upper()
                def_name = f"{prefix}{clean_name}"
                assert def_name in defines, f"Symbol {sym_name} from JSON missing in header as {def_name}"
                expected_addr = int(sym_info["addr"], 16)
                actual_addr = defines[def_name]
                assert expected_addr == actual_addr, (
                    f"Address mismatch for {def_name}: JSON=0x{expected_addr:X}, Header=0x{actual_addr:X}"
                )

        # Forward check for MediaTek SiP SMC services
        smc_svcs = data.get("smc_services", {})
        for svc_name, svc_info in smc_svcs.items():
            clean_name = svc_name.upper()
            if "fid64" in svc_info:
                fid_def = f"SMC_FID_{clean_name}"
                assert fid_def in defines, f"Missing {fid_def} in header"
                assert int(svc_info["fid64"], 16) == defines[fid_def]
            if "fid32" in svc_info:
                fid32_def = f"SMC_FID_{clean_name}_AARCH32"
                assert fid32_def in defines, f"Missing {fid32_def} in header"
                assert int(svc_info["fid32"], 16) == defines[fid32_def]
            if "addr" in svc_info:
                addr_def = f"ADDR_ATF_SMC_{clean_name}"
                assert addr_def in defines, f"Missing {addr_def} in header"
                assert int(svc_info["addr"], 16) == defines[addr_def]

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
            elif def_name.startswith("ADDR_ATF_SMC_"):
                svc_key = def_name[len("ADDR_ATF_SMC_"):]
                assert svc_key in smc_svcs, f"Header define {def_name} not found in smc_services"
            elif def_name.startswith("ADDR_ATF_"):
                sym_key = def_name[len("ADDR_ATF_"):].lower()
                if sym_key == "entry": sym_key = "_start"
                assert sym_key in data.get("symbols", {}).get("atf", {}), f"Header define {def_name} not found in JSON symbols.atf"
            elif def_name.startswith("ADDR_PL_"):
                sym_key = def_name[len("ADDR_PL_"):].lower()
                if sym_key == "entry": sym_key = "_start"
                assert sym_key in data.get("symbols", {}).get("preloader", {}), f"Header define {def_name} not found in JSON symbols.preloader"
            elif def_name.startswith("SMC_FID_"):
                fid_key = def_name[len("SMC_FID_"):]
                if fid_key.endswith("_AARCH32"):
                    fid_key = fid_key[:-len("_AARCH32")]
                assert fid_key in smc_svcs, f"Header define {def_name} not found in smc_services"
            elif def_name.startswith("TEE_A_") or def_name.startswith("TEE_B_") or def_name.startswith("PRELOADER_"):
                pass

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

def verify_tee_binary(data, tee_img_path):
    print(f"\n[*] Auditing stock TEE firmware binary: {tee_img_path}")
    with open(tee_img_path, "rb") as f:
        img_bytes = f.read()

    sha256 = hashlib.sha256(img_bytes).hexdigest()
    print(f"    Container size: {len(img_bytes):,} bytes")
    print(f"    Container SHA256: {sha256}")
    if "stock_tee_sha256" in data:
        assert sha256.lower() == data["stock_tee_sha256"].lower(), (
            f"TEE SHA256 mismatch! Expected {data['stock_tee_sha256']}, got {sha256}"
        )

    # Check atf subpartition header
    if "atf" in data.get("subpartitions", {}):
        atf_sub = data["subpartitions"]["atf"]
        hdr_ofs = int(atf_sub.get("header_offset", atf_sub["offset"]), 16)
        hdr = parse_mkimg_header(img_bytes, hdr_ofs)
        assert hdr is not None, f"Could not parse mkimg header at 0x{hdr_ofs:06X} for atf"
        assert hdr.magic == MKIMG_MAGIC, f"Invalid mkimg magic at 0x{hdr_ofs:06X} for atf"
        assert hdr.payload_size == atf_sub["size_bytes"], "mkimg size mismatch for atf"
        print(f"      [        atf] Header @ 0x{hdr_ofs:06X} -> Payload: 0x{hdr.payload_offset:06X}..0x{hdr.payload_offset+hdr.payload_size:06X} ({hdr.payload_size:,} bytes)")

        # Verify VBAR_EL3 instruction in ATF entry
        atf_bin = img_bytes[hdr.payload_offset : hdr.payload_offset + hdr.payload_size]
        atf_base = int(atf_sub["load_addr"], 16)
        if "vbar_el3" in data.get("symbols", {}).get("atf", {}):
            expected_vbar = int(data["symbols"]["atf"]["vbar_el3"]["addr"], 16)
            insn_w = struct.unpack_from("<I", atf_bin, 0x10)[0]
            immlo = (insn_w >> 29) & 0x3
            immhi = (insn_w >> 5) & 0x7FFFF
            imm = (immhi << 2) | immlo
            if imm & (1 << 20):
                imm -= (1 << 21)
            actual_vbar = atf_base + 0x10 + imm
            assert actual_vbar == expected_vbar, f"VBAR_EL3 mismatch: actual=0x{actual_vbar:X}, expected=0x{expected_vbar:X}"
            print(f"      [   vbar_el3] Validated Secure EL3 vector table: 0x{actual_vbar:016X}")

        # Verify MTK_SIP_KERNEL_BOOT in SiP table
        sip_target = struct.pack("<II", 0x82000115, 0xC2000115)
        assert sip_target in atf_bin, "MTK_SIP_KERNEL_BOOT FIDs not found in ATF payload"
        print("      [sip_service] Validated MTK_SIP_KERNEL_BOOT (0xC2000115 / 0x82000115) in ATF payload")

    print("    -> All TEE binary assertions verified successfully.")

def verify_preloader_binary(data, pl_img_path):
    print(f"\n[*] Auditing stock Preloader firmware binary: {pl_img_path}")
    with open(pl_img_path, "rb") as f:
        img_bytes = f.read()

    sha256 = hashlib.sha256(img_bytes).hexdigest()
    print(f"    Container size: {len(img_bytes):,} bytes")
    print(f"    Container SHA256: {sha256}")
    if "stock_preloader_sha256" in data:
        assert sha256.lower() == data["stock_preloader_sha256"].lower(), (
            f"Preloader SHA256 mismatch! Expected {data['stock_preloader_sha256']}, got {sha256}"
        )

    # Check preloader subpartition and GFH header
    if "preloader" in data.get("subpartitions", {}):
        pl_sub = data["subpartitions"]["preloader"]
        hdr_ofs = int(pl_sub.get("header_offset", "0x001000"), 16)
        gfh = parse_gfh_header(img_bytes, hdr_ofs)
        assert gfh is not None, f"Could not parse GFH header at 0x{hdr_ofs:06X} for preloader"
        assert gfh.magic == GFH_MAGIC, f"Invalid GFH magic at 0x{hdr_ofs:06X} for preloader"
        assert gfh.load_addr == 0x00200F10, f"Unexpected GFH load_addr: 0x{gfh.load_addr:08X}"
        assert gfh.jump_offset == 0xF0, f"Unexpected GFH jump_offset: 0x{gfh.jump_offset:X}"

        entry_va = gfh.load_addr + gfh.jump_offset
        expected_entry = int(pl_sub["load_addr"], 16)
        assert entry_va == expected_entry, f"Preloader entry VA mismatch: 0x{entry_va:08X} vs 0x{expected_entry:08X}"
        print(f"      [     gfh_hdr] Header @ 0x{hdr_ofs:06X} -> Load Addr: 0x{gfh.load_addr:08X}, Entry: 0x{entry_va:08X}")

        # Check payload offset and size
        payload_ofs = hdr_ofs + gfh.hdr_size
        expected_payload_ofs = int(pl_sub["payload_offset"], 16)
        assert payload_ofs == expected_payload_ofs, f"Payload offset mismatch: 0x{payload_ofs:X} vs 0x{expected_payload_ofs:X}"

        payload_size = gfh.total_size - gfh.hdr_size - gfh.sig_size
        expected_payload_size = int(pl_sub["payload_size"], 16)
        assert payload_size == expected_payload_size, f"Payload size mismatch: 0x{payload_size:X} vs 0x{expected_payload_size:X}"
        print(f"      [   pl_binary] Payload: 0x{payload_ofs:06X}..0x{payload_ofs+payload_size:06X} ({payload_size:,} bytes)")

        # Verify entry branch instruction: 0x10F4 has 'b #0x201020' (0xEA000005)
        branch_insn = struct.unpack_from("<I", img_bytes, payload_ofs + 4)[0]
        assert branch_insn == 0xEA000005, f"Expected entry branch 0xEA000005 at 0x{payload_ofs+4:06X}, got 0x{branch_insn:08X}"
        print("      [entry_branch] Validated AArch32 entry branch (b #0x201020) at entry+4")

        # Verify trailing unallocated zero region
        total_used = hdr_ofs + gfh.total_size
        trailing_free = len(img_bytes) - total_used
        if trailing_free > 0:
            assert img_bytes[total_used:] == b"\x00" * trailing_free, "Preloader trailing flash space contains non-zero data!"
            print(f"      [ flash_zeros] Validated {trailing_free:,} bytes (~{trailing_free/1024/1024:.2f} MiB) trailing unallocated flash space (100% 0x00)")

    print("    -> All Preloader binary assertions verified successfully.")

def main():
    print("=" * 64)
    print(" Loki Stock Symbol & Architecture Consistency Verifier")
    print("=" * 64)

    device_files = glob.glob(os.path.join(DEVICES_DIR, "**", "*.json"), recursive=True)
    if not device_files:
        print("[!] No device JSON profiles found in devices/")
        sys.exit(1)

    target_fw = locate_firmware_image(sys.argv[1] if len(sys.argv) > 1 else None, REPO_ROOT)
    target_tee = locate_tee_image(None, REPO_ROOT)
    target_pl = locate_preloader_image(None, REPO_ROOT)

    for json_path in device_files:
        data = verify_device(json_path)

        if target_fw:
            verify_binary(data, target_fw)
        else:
            print("\n[*] Notice: No firmware image provided; skipping binary assertions.")
            print("    Set LOKI_FIRMWARE_IMG=<path/to/lk.img> to run binary audits.")

        if target_tee:
            verify_tee_binary(data, target_tee)

        if target_pl:
            verify_preloader_binary(data, target_pl)

    print("\n[+] ALL DEVICE CONSISTENCY & REVERSE-ENGINEERING CHECKS PASSED.")

if __name__ == "__main__":
    main()
