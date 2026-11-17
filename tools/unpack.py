#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
unpack.py — MediaTek Composite lk.img Subpartition Extractor

Scans for the MTK mkimg header (magic 0x58881688) across the composite container,
identifies each sub-image (lk, bl2_ext, aee, lk_main_dtb, cert1, cert2), and extracts
clean raw binaries ready for analysis in Ghidra, radare2, rizin, or Capstone.
"""

import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import MKIMG_HDR_SIZE, iter_mkimg_headers

def unpack_lk(image_path, out_dir):
    with open(image_path, "rb") as f:
        data = f.read()

    full_sha = hashlib.sha256(data).hexdigest()
    print(f"[*] Input: {image_path} ({len(data):,} bytes)")
    print(f"[*] Container SHA-256: {full_sha}\n")
    os.makedirs(out_dir, exist_ok=True)

    found_parts = []
    for subpart_index, hdr in enumerate(iter_mkimg_headers(data)):
        name = hdr.name if hdr.name else f"subpart_{subpart_index}"
        payload = data[hdr.payload_offset : hdr.payload_offset + hdr.payload_size]
        part_sha = hashlib.sha256(payload).hexdigest()

        out_filename = f"{subpart_index:02d}_{name}.bin"
        out_path = os.path.join(out_dir, out_filename)
        with open(out_path, "wb") as out_f:
            out_f.write(payload)

        print(f"  [{subpart_index:02d}] Offset: 0x{hdr.header_offset:06X} | Name: {name:<14} | Size: {hdr.payload_size:>8,} B | SHA: {part_sha[:16]}... -> {out_filename}")
        found_parts.append((hdr.header_offset, name, hdr.payload_size, out_path))

    if found_parts:
        last_offset, last_name, last_size, _ = found_parts[-1]
        last_end = last_offset + MKIMG_HDR_SIZE + last_size
        if last_end < len(data):
            trailing_size = len(data) - last_end
            print(f"\n[*] Trailing unallocated flash space: 0x{last_end:06X} .. 0x{len(data):06X} ({trailing_size:,} bytes / {trailing_size/(1024*1024):.2f} MiB)")
            print("    (Recommended custom stage / loki-loader offset: 0x210000)")

    print(f"\n[+] Successfully extracted {len(found_parts)} subpartitions to: {out_dir}")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path/to/lk.img> [output_directory]")
        sys.exit(1)

    image_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "extracted"
    unpack_lk(image_path, out_dir)

if __name__ == "__main__":
    main()
