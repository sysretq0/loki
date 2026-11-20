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

# Standard Load Addresses (MediaTek AArch64 / AArch32)
DEFAULT_LOAD_VIRT = {
    "lk": 0xFFFF000050F00000,
    "lk_aarch32": 0x4C400000,
    "bl2_ext": 0xFFFF000062F00000,
    "aee": 0xFFFF000063F00000,
    "atf": 0x0000000048200000,
    "tee": 0x0000000070000000,
    "preloader": 0x0000000000201000,
}

# MediaTek Preloader GFH Constants
GFH_MAGIC = 0x014D4D4D  # "MMM\x01"
GFH_HDR_SIZE = 0xF0     # 240 bytes standard GFH block

# Device Tree / Android DT Table Constants
DT_TABLE_MAGIC = 0xd7b7ab1e
FDT_MAGIC = 0xd00dfeed

DtTableHeader = namedtuple(
    "DtTableHeader",
    ["magic", "total_size", "hdr_size", "entry_size", "entry_count", "entries_offset", "page_size", "version"]
)

def parse_dt_table_header(buffer: bytes, offset: int = 0) -> Optional[DtTableHeader]:
    """
    Parses an Android DT table header (magic: 0xd7b7ab1e) at the given offset.
    Returns DtTableHeader namedtuple or None if invalid.
    """
    if offset + 32 > len(buffer):
        return None
    magic, total_size, hdr_size, entry_size, entry_count, entries_offset, page_size, version = struct.unpack_from(">8I", buffer, offset)
    if magic != DT_TABLE_MAGIC:
        return None
    return DtTableHeader(
        magic=magic,
        total_size=total_size,
        hdr_size=hdr_size,
        entry_size=entry_size,
        entry_count=entry_count,
        entries_offset=entries_offset,
        page_size=page_size,
        version=version
    )

def extract_dtbo_entry(buffer: bytes, index: int = 0) -> Optional[bytes]:
    """
    Extracts the raw FDT payload for entry `index` from a dtbo.img container.
    """
    hdr = parse_dt_table_header(buffer, 0)
    if not hdr or index >= hdr.entry_count:
        return None
    e_pos = hdr.entries_offset + index * hdr.entry_size
    if e_pos + 8 > len(buffer):
        return None
    dt_size, dt_offset = struct.unpack_from(">2I", buffer, e_pos)
    if dt_offset + dt_size > len(buffer):
        return None
    return buffer[dt_offset : dt_offset + dt_size]

def extract_vendor_boot_dtb(buffer: bytes) -> Optional[bytes]:
    """
    Extracts the base device tree blob from an Android vendor_boot image (v3/v4).
    Resolves both raw FDT blobs and nested Android DT table headers.
    """
    if len(buffer) < 2112 or buffer[:8] != b"VNDRBOOT":
        return None
    page_size = struct.unpack_from("<I", buffer, 0x0C)[0]
    ramdisk_size = struct.unpack_from("<I", buffer, 0x18)[0]
    hdr_size = struct.unpack_from("<I", buffer, 0x830)[0]
    dtb_size = struct.unpack_from("<I", buffer, 0x834)[0]

    hdr_pages = (hdr_size + page_size - 1) // page_size
    ramdisk_pages = (ramdisk_size + page_size - 1) // page_size
    dtb_offset = (hdr_pages + ramdisk_pages) * page_size

    if dtb_offset + dtb_size > len(buffer):
        return None

    dtb_blob = buffer[dtb_offset : dtb_offset + dtb_size]
    if len(dtb_blob) >= 4 and dtb_blob[:4] == struct.pack(">I", DT_TABLE_MAGIC):
        return extract_dtbo_entry(dtb_blob, 0)
    elif len(dtb_blob) >= 4 and dtb_blob[:4] == struct.pack(">I", FDT_MAGIC):
        return dtb_blob

    return None

GfhFileInfo = namedtuple(
    "GfhFileInfo",
    ["offset", "magic", "file_type", "flash_dev", "sig_type", "load_addr", "total_size", "hdr_size", "sig_size", "jump_offset"]
)

def parse_gfh_header(buffer: bytes, offset: int = 0x1000) -> Optional[GfhFileInfo]:
    """
    Parses a MediaTek GFH (General File Header) block at the given offset (default: 0x1000).
    Returns GfhFileInfo namedtuple or None if invalid.
    """
    if offset + 56 > len(buffer):
        return None

    magic, sec_size, sec_type = struct.unpack_from("<IHH", buffer, offset)
    if magic != GFH_MAGIC or sec_type != 0:
        return None

    f_type, flash_dev, sig_type = struct.unpack_from("<HBB", buffer, offset + 24)
    load_addr, total_size, max_size, hdr_size, sig_size, jump_offset = struct.unpack_from("<IIIIII", buffer, offset + 28)

    return GfhFileInfo(
        offset=offset,
        magic=magic,
        file_type=f_type,
        flash_dev=flash_dev,
        sig_type=sig_type,
        load_addr=load_addr,
        total_size=total_size,
        hdr_size=hdr_size,
        sig_size=sig_size,
        jump_offset=jump_offset
    )

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

def locate_tee_image(arg: Optional[str] = None, repo_root: Optional[str] = None) -> Optional[str]:
    """
    Resolves the stock tee.img container path across:
    1. CLI argument override
    2. LOKI_TEE_IMG environment variable
    3. Sibling of firmware image or common directories
    """
    if arg:
        if os.path.exists(arg):
            return os.path.abspath(arg)
        print(f"[!] Warning: Specified TEE image '{arg}' not found.")
        return None

    env_tee = os.environ.get("LOKI_TEE_IMG")
    if env_tee:
        if os.path.exists(env_tee):
            return os.path.abspath(env_tee)
        print(f"[!] Warning: LOKI_TEE_IMG='{env_tee}' not found.")
        return None

    if repo_root is None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    candidates = [
        os.path.join(repo_root, "firmware", "tee.img"),
        "/work/firmware/advan_x1/tee.img",
        "/work/firmware/advan_x1_v4/tee.img",
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)

    return None

def locate_preloader_image(arg: Optional[str] = None, repo_root: Optional[str] = None) -> Optional[str]:
    """
    Resolves the stock preloader image path across:
    1. CLI argument override
    2. LOKI_PRELOADER_IMG environment variable
    3. Common repository / system firmware directories
    """
    if arg:
        if os.path.exists(arg):
            return os.path.abspath(arg)
        print(f"[!] Warning: Specified preloader '{arg}' not found.")
        return None

    env_pl = os.environ.get("LOKI_PRELOADER_IMG")
    if env_pl:
        if os.path.exists(env_pl):
            return os.path.abspath(env_pl)
        print(f"[!] Warning: LOKI_PRELOADER_IMG='{env_pl}' not found.")
        return None

    if repo_root is None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    candidates = [
        os.path.join(repo_root, "firmware", "preloader.img"),
        "/work/firmware/advan_x1/preloader.img",
        "/work/firmware/advan_x1_v4/preloader_k6789v1_64.bin",
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)

    return None

def locate_dtbo_image(arg: Optional[str] = None, repo_root: Optional[str] = None) -> Optional[str]:
    """
    Resolves the stock dtbo.img container path across:
    1. CLI argument override
    2. LOKI_DTBO_IMG environment variable
    3. Common repository / system firmware directories
    """
    if arg:
        if os.path.exists(arg):
            return os.path.abspath(arg)
        print(f"[!] Warning: Specified DTBO image '{arg}' not found.")
        return None

    env_dtbo = os.environ.get("LOKI_DTBO_IMG")
    if env_dtbo:
        if os.path.exists(env_dtbo):
            return os.path.abspath(env_dtbo)
        print(f"[!] Warning: LOKI_DTBO_IMG='{env_dtbo}' not found.")
        return None

    if repo_root is None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    candidates = [
        os.path.join(repo_root, "firmware", "dtbo.img"),
        "/work/firmware/advan_x1/dtbo.img",
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)

    return None

def locate_vendor_boot_image(arg: Optional[str] = None, repo_root: Optional[str] = None) -> Optional[str]:
    """
    Resolves the stock vendor_boot.img container path across:
    1. CLI argument override
    2. LOKI_VENDOR_BOOT_IMG environment variable
    3. Common repository / system firmware directories
    """
    if arg:
        if os.path.exists(arg):
            return os.path.abspath(arg)
        print(f"[!] Warning: Specified vendor_boot image '{arg}' not found.")
        return None

    env_vb = os.environ.get("LOKI_VENDOR_BOOT_IMG")
    if env_vb:
        if os.path.exists(env_vb):
            return os.path.abspath(env_vb)
        print(f"[!] Warning: LOKI_VENDOR_BOOT_IMG='{env_vb}' not found.")
        return None

    if repo_root is None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    candidates = [
        os.path.join(repo_root, "firmware", "vendor_boot.img"),
        "/work/firmware/advan_x1/vendor_boot.img",
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

def is_arm32_bl(ins_word: int) -> bool:
    """
    Checks if a 32-bit ARM instruction word is a Branch with Link (BL).
    Condition field is bits [31:28], opcode bits [27:24] == 1011 (0xB).
    """
    return (ins_word & 0x0F000000) == 0x0B000000

def is_arm32_b(ins_word: int) -> bool:
    """
    Checks if a 32-bit ARM instruction word is an unconditional/conditional Branch (B).
    Condition field is bits [31:28], opcode bits [27:24] == 1010 (0xA).
    """
    return (ins_word & 0x0F000000) == 0x0A000000

def decode_arm32_branch_target(ins_word: int, pc: int) -> int:
    """
    Decodes the 24-bit signed immediate from an ARM32 B or BL instruction
    and returns the calculated absolute branch destination virtual address.
    In ARM state, PC is address of instruction + 8.
    """
    imm24 = ins_word & 0x00FFFFFF
    if imm24 & 0x00800000:
        imm24 -= 0x01000000
    return pc + 8 + (imm24 << 2)

def is_thumb_bl(w1: int, w2: int) -> bool:
    """
    Checks if a 32-bit Thumb-2 instruction pair is BL or BLX.
    w1: bits [15:11] == 11110 (0xF000..0xF7FF)
    w2: bits [15:14] == 11, bit 12 == 1 (0xD000..0xFFFF)
    """
    return (w1 & 0xF800) == 0xF000 and (w2 & 0xD000) == 0xD000

def decode_thumb_branch_target(w1: int, w2: int, pc: int) -> int:
    """
    Decodes 32-bit Thumb-2 BL/BLX branch destination virtual address.
    In Thumb state, PC is address of instruction + 4.
    """
    s = (w1 >> 10) & 1
    imm10 = w1 & 0x3FF
    j1 = (w2 >> 13) & 1
    j2 = (w2 >> 11) & 1
    imm11 = w2 & 0x7FF
    i1 = ~(j1 ^ s) & 1
    i2 = ~(j2 ^ s) & 1
    imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
    if s:
        imm32 -= (1 << 25)
    return pc + 4 + imm32

def detect_binary_arch(buffer: bytes) -> str:
    """
    Heuristically determines whether raw LK binary is AArch32 or AArch64.
    Checks vector table format and entry instructions.
    """
    if len(buffer) >= 8:
        # AArch32 standard vector: 'b 0x24' -> 0xEA000007 (\x07\x00\x00\xea)
        # or first word starts with 0xEA (ARM32 unconditional branch)
        first_word = struct.unpack_from("<I", buffer, 0)[0]
        if (first_word & 0xFF000000) == 0xEA000000:
            return "aarch32"
    return "aarch64"

