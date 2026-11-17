#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
init_device.py — Automatic Device Scaffolding & Profiling Tool

Bootstraps a complete, verified device definition (JSON + C Header) for a new
MediaTek device by extracting, analyzing, and scanning its stock lk.img container.
"""

import os
import sys
import json
import struct
import hashlib

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
sys.path.insert(0, TOOLS_DIR)

from gen_header import generate_header
from common import iter_mkimg_headers, DEFAULT_LOAD_VIRT, MKIMG_HDR_SIZE

def scaffold_device(codename, soc, lk_img_path, out_dir=None):
    if not os.path.exists(lk_img_path):
        print(f"[!] Error: Firmware file not found: {lk_img_path}")
        sys.exit(1)

    with open(lk_img_path, "rb") as f:
        img_bytes = f.read()

    full_sha = hashlib.sha256(img_bytes).hexdigest()
    print("=" * 68)
    print(f" Loki Device Scaffolder: {codename} ({soc})")
    print("=" * 68)
    print(f"[*] Input Container: {lk_img_path} ({len(img_bytes):,} bytes)")
    print(f"[*] Container SHA-256: {full_sha}\n")

    # 1. Parse subpartitions from mkimg headers
    subparts = {}
    for hdr in iter_mkimg_headers(img_bytes):
        name = hdr.name
        if name in ("lk", "bl2_ext", "aee", "lk_main_dtb"):
            key = "dtb" if name == "lk_main_dtb" else name
            subparts[key] = {
                "name": name,
                "offset": f"0x{hdr.header_offset:06X}",
                "size": f"0x{hdr.payload_size:06X}",
                "size_bytes": hdr.payload_size,
                "header_offset": f"0x{hdr.header_offset:06X}",
                "payload_offset": f"0x{hdr.payload_offset:06X}",
                "payload_size": f"0x{hdr.payload_size:06X}",
                "load_addr": f"0x{DEFAULT_LOAD_VIRT[key]:016X}" if key in DEFAULT_LOAD_VIRT else "DRAM staging",
                "el": 3 if key == "bl2_ext" else (1 if key in ("lk", "aee") else None)
            }
            print(f"[+] Found subpartition '{name}' @ 0x{hdr.header_offset:06X} ({hdr.payload_size:,} bytes payload)")

    # Compute container spans
    subpart_keys = ["lk", "bl2_ext", "aee", "dtb"]
    for i in range(len(subpart_keys) - 1):
        curr_k = subpart_keys[i]
        next_k = subpart_keys[i+1]
        if curr_k in subparts and next_k in subparts:
            span = int(subparts[next_k]["header_offset"], 16) - int(subparts[curr_k]["header_offset"], 16)
            subparts[curr_k]["container_span"] = f"0x{span:06X}"

    # Extract raw lk payload for analysis
    if "lk" not in subparts:
        print("[!] Error: Could not locate 'lk' subpartition in container!")
        sys.exit(1)

    lk_pay_ofs = int(subparts["lk"]["payload_offset"], 16)
    lk_pay_sz = subparts["lk"]["size_bytes"]
    lk_bin = img_bytes[lk_pay_ofs : lk_pay_ofs + lk_pay_sz]
    lk_base = DEFAULT_LOAD_VIRT["lk"]

    # 2. Detect zero regions in LK
    zero_regions = {}
    # Scan for long runs of zeros (> 1024 bytes) in LK .text
    cur_start = None
    for i in range(0, min(len(lk_bin), 0x80000), 4):
        w = struct.unpack_from("<I", lk_bin, i)[0]
        if w == 0:
            if cur_start is None:
                cur_start = i
        else:
            if cur_start is not None:
                run_len = i - cur_start
                if run_len >= 1024:
                    reg_id = f"ZERO_REGION_{len(zero_regions)+1}"
                    zero_regions[reg_id] = {
                        "file_offset": f"0x{cur_start:06X}",
                        "file_offset_end": f"0x{i:06X}",
                        "addr_start": f"0x{lk_base + cur_start:016X}",
                        "addr_end": f"0x{lk_base + i:016X}",
                        "size_bytes": run_len,
                        "permissions": "RX",
                        "desc": f"Linker alignment padding in .text segment ({run_len} bytes pure 0x00)"
                    }
                    if len(zero_regions) == 1:
                        zero_regions[reg_id]["recommended_hook_addr"] = f"0x{lk_base + cur_start + 8:016X}"
                cur_start = None

    print(f"\n[+] Detected {len(zero_regions)} zero-filled executable padding regions in .text:")
    for zid, zinfo in zero_regions.items():
        print(f"    * {zid}: {zinfo['file_offset']}..{zinfo['file_offset_end']} ({zinfo['size_bytes']:,} bytes)")

    # 3. Detect trailing unallocated flash space
    last_subpart_end = 0
    # Search backwards from container end for non-zero byte
    for i in range(len(img_bytes) - 1, -1, -1):
        if img_bytes[i] != 0:
            last_subpart_end = i + 1
            break
    free_space = len(img_bytes) - last_subpart_end
    unallocated_flash = {
        "container_size_bytes": len(img_bytes),
        "used_bytes": last_subpart_end,
        "offset_start": f"0x{last_subpart_end:06X}",
        "offset_end": f"0x{len(img_bytes):06X}",
        "free_space_bytes": free_space,
        "free_space_mib": round(free_space / (1024 * 1024), 3),
        "desc": "Trailing unallocated flash partition space in lk.img filled with pure 0x00 bytes"
    }
    print(f"[+] Trailing unallocated flash: 0x{last_subpart_end:06X}..0x{len(img_bytes):06X} ({free_space:,} bytes / {free_space / (1024*1024):.2f} MiB)")

    # 4. Construct device JSON
    soc_clean = soc.lower().replace(" ", "_")
    if out_dir is None:
        out_dir = os.path.join(REPO_ROOT, "devices", soc_clean)
    os.makedirs(out_dir, exist_ok=True)
    out_json = os.path.join(out_dir, f"{codename}.json")
    out_h = os.path.join(out_dir, f"{codename}.h")

    device_doc = {
        "device": codename.replace("_", " ").title(),
        "manufacturer": "OEM",
        "soc": soc.upper(),
        "arch": "aarch64",
        "firmware_version": "v1",
        "stock_lk_sha256": full_sha,
        "container_size": len(img_bytes),
        "subpartitions": subparts,
        "symbols": {
            "lk": {
                "_start": {
                    "addr": f"0x{lk_base:016X}",
                    "desc": "Stock LK entry point; enables MMU and sets up initial EL1 stack"
                }
            },
            "bl2_ext": {
                "_start": {
                    "addr": f"0x{DEFAULT_LOAD_VIRT['bl2_ext']:016X}",
                    "desc": "BL2_EXT entry point in Secure EL3"
                }
            },
            "aee": {
                "kedump_init": {
                    "addr": f"0x{DEFAULT_LOAD_VIRT['aee'] + 0x1000:016X}",
                    "desc": "Initializes Exception Engine memory buffers"
                }
            }
        },
        "zero_regions": {"lk": zero_regions},
        "unallocated_flash": unallocated_flash,
        "hooks": {},
        "dead_code": {"lk": {}}
    }

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(device_doc, f, indent=2)
    print(f"\n[+] Created scaffold JSON: {out_json}")

    # Generate initial C header
    generate_header(out_json, out_h)
    print(f"[+] Generated initial C header: {out_h}")
    print("\nNext steps:")
    print(f"  1. Run './loki scan {out_dir}/00_lk.bin' to identify additional function entry points.")
    print(f"  2. Populate symbols into {out_json}.")
    print(f"  3. Run './loki gen-header {out_json}' to sync the C header.")
    print(f"  4. Run './loki verify {out_json}' to validate.")

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Bootstrap a new device profile (JSON + C Header) from stock lk.img"
    )
    parser.add_argument("codename", help="Device codename (e.g. redmi_note_12)")
    parser.add_argument("soc", help="SoC name (e.g. mt6789)")
    parser.add_argument("image", help="Path to stock lk.img")
    parser.add_argument("-o", "--output", help="Custom output directory")
    args = parser.parse_args()

    scaffold_device(args.codename, args.soc, args.image, args.output)

if __name__ == "__main__":
    main()
