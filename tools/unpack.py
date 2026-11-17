#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
unpack.py — MediaTek Composite lk.img Subpartition Extractor

Scans for the MTK mkimg header (magic 0x58881688) across the composite container,
identifies each sub-image (lk, bl2_ext, aee, lk_main_dtb, cert1, cert2), and extracts
clean raw binaries ready for analysis in Ghidra, radare2, rizin, or Capstone.
"""

import sys
import os
import struct
import hashlib

MKIMG_MAGIC = 0x58881688
MKIMG_HDR_SIZE = 512

def unpack_lk(image_path, out_dir):
    with open(image_path, "rb") as f:
        data = f.read()

    full_sha = hashlib.sha256(data).hexdigest()
    print(f"[*] Input: {image_path} ({len(data):,} bytes)")
    print(f"[*] Container SHA-256: {full_sha}\n")
    os.makedirs(out_dir, exist_ok=True)

    pos = 0
    subpart_index = 0
    found_parts = []
    magic_bytes = struct.pack("<I", MKIMG_MAGIC)

    while True:
        idx = data.find(magic_bytes, pos)
        if idx == -1:
            break

        if idx + MKIMG_HDR_SIZE > len(data):
            break

        magic, size = struct.unpack_from("<II", data, idx)
        name_raw = data[idx + 8 : idx + 40]
        name = name_raw.split(b"\x00")[0].decode("ascii", errors="replace").strip()
        if not name:
            name = f"subpart_{subpart_index}"

        payload_offset = idx + MKIMG_HDR_SIZE
        payload = data[payload_offset : payload_offset + size]
        part_sha = hashlib.sha256(payload).hexdigest()

        out_filename = f"{subpart_index:02d}_{name}.bin"
        out_path = os.path.join(out_dir, out_filename)
        with open(out_path, "wb") as out_f:
            out_f.write(payload)

        print(f"  [{subpart_index:02d}] Offset: 0x{idx:06X} | Name: {name:<14} | Size: {size:>8,} B | SHA: {part_sha[:16]}... -> {out_filename}")
        found_parts.append((idx, name, size, out_path))
        subpart_index += 1
        pos = idx + MKIMG_HDR_SIZE + size

    if found_parts:
        last_offset, last_name, last_size, _ = found_parts[-1]
        last_end = last_offset + MKIMG_HDR_SIZE + last_size
        if last_end < len(data):
            trailing_size = len(data) - last_end
            print(f"\n[*] Trailing unallocated flash space: 0x{last_end:06X} .. 0x{len(data):06X} ({trailing_size:,} bytes / {trailing_size/(1024*1024):.2f} MiB)")
            print(f"    (Recommended custom stage / loki-loader offset: 0x210000)")

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
