#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
common.py — Shared Utilities, Container Parsers, and Architecture Helpers

Centralizes shared constants, MediaTek mkimg container parsing, firmware locator,
string scanning, and AArch64 instruction decoding routines across the Loki toolchain.
"""

import os
import sys
import struct
from collections import namedtuple
from typing import Optional, List, Iterator, Union

# MediaTek mkimg Container Constants
MKIMG_MAGIC = 0x58881688
MKIMG_HDR_SIZE = 512
DEFAULT_CONTAINER_SIZE = 0x400000  # 4 MiB flash partition

# Standard Load Addresses (MediaTek AArch64)
DEFAULT_LOAD_VIRT = {
    "lk": 0xFFFF000050F00000,
    "bl2_ext": 0xFFFF000062F00000,
    "aee": 0xFFFF000063F00000,
}

# Subpartition Header Structure
MkImgHeader = namedtuple(
    "MkImgHeader",
    ["header_offset", "payload_offset", "payload_size", "name", "magic"]
)

def parse_mkimg_header(buffer: bytes, offset: int = 0) -> Optional[MkImgHeader]:
    """
    Parses a 512-byte MediaTek mkimg header at the given offset.
    Returns MkImgHeader namedtuple or None if invalid or truncated.
    """
    if offset + MKIMG_HDR_SIZE > len(buffer):
        return None

    magic, dsize = struct.unpack_from("<II", buffer, offset)
    if magic != MKIMG_MAGIC:
        return None

    name_raw = buffer[offset + 8 : offset + 40]
    name = name_raw.split(b"\x00")[0].decode("ascii", errors="replace").strip()
    payload_offset = offset + MKIMG_HDR_SIZE

    return MkImgHeader(
        header_offset=offset,
        payload_offset=payload_offset,
        payload_size=dsize,
        name=name,
        magic=magic
    )

def iter_mkimg_headers(data: bytes) -> Iterator[MkImgHeader]:
    """
    Iterates over all valid MediaTek mkimg headers in a container image.
    Scans forward sequentially, advancing past payloads or searching for magic.
    """
    pos = 0
    magic_bytes = struct.pack("<I", MKIMG_MAGIC)
    length = len(data)

    while pos < length:
        hdr = parse_mkimg_header(data, pos)
        if hdr:
            yield hdr
            # Advance past header and payload
            pos = hdr.payload_offset + hdr.payload_size
        else:
            # Search for next occurrence of magic
            next_idx = data.find(magic_bytes, pos + 1)
            if next_idx == -1:
                break
            pos = next_idx

def extract_subpartition(data: bytes, subpart_name: str) -> Optional[bytes]:
    """
    Extracts raw payload bytes for a specific named subpartition (e.g. 'lk', 'bl2_ext').
    """
    for hdr in iter_mkimg_headers(data):
        if hdr.name == subpart_name or (subpart_name == "dtb" and hdr.name == "lk_main_dtb"):
            end = hdr.payload_offset + hdr.payload_size
            if end <= len(data):
                return data[hdr.payload_offset : end]
    return None

def locate_firmware_image(arg: Optional[str] = None, repo_root: Optional[str] = None) -> Optional[str]:
    """
    Resolves the stock lk.img container path across:
    1. CLI argument override
    2. LOKI_FIRMWARE_IMG environment variable
    3. Common repository / system firmware directories
    """
    if arg:
        if os.path.exists(arg):
            return os.path.abspath(arg)
        print(f"[!] Warning: Specified firmware '{arg}' not found.")
        return None

    env_fw = os.environ.get("LOKI_FIRMWARE_IMG")
    if env_fw:
        if os.path.exists(env_fw):
            return os.path.abspath(env_fw)
        print(f"[!] Warning: LOKI_FIRMWARE_IMG='{env_fw}' not found.")
        return None

    if repo_root is None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    candidates = [
        os.path.join(repo_root, "firmware", "lk.img"),
        "/work/firmware/advan_x1/lk.img",
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)

    return None

def find_string_offsets(data: bytes, text: Union[str, bytes]) -> List[int]:
    """
    Finds all byte offsets of a string or byte needle within a binary.
    """
    needle = text.encode("utf-8") if isinstance(text, str) else text
    offsets = []
    pos = 0
    while True:
        idx = data.find(needle, pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + len(needle)
    return offsets

def is_aarch64_bl(ins_word: int) -> bool:
    """
    Checks if a 32-bit AArch64 instruction word is a Branch with Link (BL).
    Opcode pattern: 1001 01xx xxxx xxxx xxxx xxxx xxxx xxxx (0x94000000..0x97FFFFFF)
    """
    return (ins_word & 0xFC000000) == 0x94000000

def is_aarch64_b(ins_word: int) -> bool:
    """
    Checks if a 32-bit AArch64 instruction word is an unconditional Branch (B).
    Opcode pattern: 0001 01xx xxxx xxxx xxxx xxxx xxxx xxxx (0x14000000..0x17FFFFFF)
    """
    return (ins_word & 0xFC000000) == 0x14000000

def decode_aarch64_branch_target(ins_word: int, pc: int) -> int:
    """
    Decodes the 26-bit immediate displacement from an AArch64 B or BL instruction
    and returns the calculated absolute branch destination virtual address.
    """
    imm26 = ins_word & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + (imm26 << 2)
