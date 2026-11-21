#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Attribution & License Compliance:
#   The MediaTek cert2 ASN.1 context [0] hash-override OIDs/DER structure and
#   Fenrir security policy bypass needle patterns are derived from liblk / Fenrir
#   by Roger Ortiz (R0rt1z2), licensed under GNU GPL v3.0.
#   See LICENSE in the repository root for full GPL-3.0 terms.
"""
loki-pack.py — Verified MediaTek composite lk.img packer & payload config generator.

Features:
  1. Generates assembly/linker/C-safe device_config.h directly from devices/<soc>/<device>.json.
  2. Enforces pinned stock_lk_sha256 and verifies stock pivot BL opcode before patching.
  3. Injects Stage-1 cave payload into verified hardware dead-code cave (DEADCODE_MSDC_EMMC).
  4. Embeds standalone bare-metal payload (e.g. U-Boot u-boot.bin) as a new 'loki_payload'
     mkimg subpartition at 0x210000 with struct loki_subpart_header + IEEE CRC32.
  5. Applies Fenrir security policy patches (and optional --unlock-el2 on bl2_ext).
  6. Applies liblk-compatible cert2 ASN.1 [0] hash overrides and self-verifies the output.

Safety invariant: this tool NEVER flashes or writes to any device.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import zlib
from hashlib import sha256
from pathlib import Path

MTK_MAGIC = 0x58881688
MTK_EXT_MAGIC = 0x58891689
MKIMG_HDR_SZ = 512

LOKI_SUBPART_OFFSET = 0x210000
LOKI_SUBPART_MAGIC = 0x494B4F4C  # "LOKI"
LOKI_SUBPART_VER = 3
LOKI_SUBPART_HDR_SZ = 64

# MTK cert2 hash override OIDs (liblk standard)
HT_OR_H_OID = bytes.fromhex("060760867693160204032100")
IMG_OR_I_OID = bytes.fromhex("060760867693160201032100")

# Fenrir / MediaTek security policy bypass patterns (AArch64)
SECURITY_PATCHES = {
    "force_green_state": (
        bytes.fromhex("00 d1 09 b9 c0 03 5f d6"),
        bytes.fromhex("1f d1 09 b9 c0 03 5f d6"),
    ),
    "bypass_security_control": (
        bytes.fromhex("e8 0b 40 b9 1f 0d 00 71 21 01 00 54"),
        bytes.fromhex("e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5"),
    ),
    "bypass_lock_control": (
        bytes.fromhex("1f 0d 00 71 21 01 00 54"),
        bytes.fromhex("1f 0d 00 71 1f 20 03 d5"),
    ),
    "dont_relock_seccfg": (
        bytes.fromhex("fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 2a 28 00 80 52"),
        bytes.fromhex("00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5"),
    ),
    "sec_get_vfy_policy": (
        bytes.fromhex("00 01 00 b4 fd 7b bf a9"),
        bytes.fromhex("00 00 80 52 c0 03 5f d6"),
    ),
    "spoof_lock_state": (
        bytes.fromhex("20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91"),
        bytes.fromhex("88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6"),
    ),
    "spoof_sboot_state": (
        bytes.fromhex("fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52"),
        bytes.fromhex("48 04 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5"),
    ),
    "disable_sctlr_wxn": (
        bytes.fromhex("29 01 6d b2 09 10 18 d5"),
        bytes.fromhex("1f 20 03 d5 09 10 18 d5"),
    ),
}

# bl2_ext EL3 -> Non-Secure EL2h SPSR drop patch (mov x4, #0x3c5 -> mov x4, #0x3c9)
BL2_EXT_SPSR_EL1_NEEDLE = bytes.fromhex("a4 78 80 d2")
BL2_EXT_SPSR_EL2_PATCH = bytes.fromhex("24 79 80 d2")


class Part:
    """Represents a subpartition inside a MediaTek mkimg container."""

    def __init__(self, name: str, offset: int, dsize: int, align: int, header: bytes, data: bytes):
        self.name = name
        self.offset = offset
        self.dsize = dsize
        self.align = align
        self.header = bytearray(header)
        self.data = bytearray(data)
        self.cert1: Part | None = None
        self.cert2: Part | None = None
        self.is_primary = True

    def update_data(self, blob: bytes) -> None:
        self.data = bytearray(blob)
        self.dsize = len(blob)
        struct.pack_into("<I", self.header, 4, self.dsize & 0xFFFFFFFF)
        if struct.unpack_from("<I", self.header, 48)[0] == MTK_EXT_MAGIC:
            struct.pack_into("<I", self.header, 72, (self.dsize >> 32) & 0xFFFFFFFF)

    def hashes(self) -> tuple[bytes, bytes]:
        pad = (-len(self.data)) % 16
        h = sha256(bytes(self.header)).digest()
        d = sha256(bytes(self.data) + b"\x00" * pad).digest()
        return h, d


def encode_bl(caller_va: int, target_va: int) -> bytes:
    offset = (target_va - caller_va) >> 2
    if offset < -(1 << 25) or offset >= (1 << 25):
        raise ValueError(f"BL target out of +-128 MiB range: 0x{caller_va:x} -> 0x{target_va:x}")
    insn = 0x94000000 | (offset & 0x03FFFFFF)
    return struct.pack("<I", insn)


def build_hash_override_block(h_oid: bytes, h: bytes, i_oid: bytes, d: bytes) -> bytes:
    body = h_oid + h + i_oid + d
    if len(body) >= 0x80:
        raise ValueError("Override block too large for short-form DER")
    return b"\xa0" + bytes([len(body)]) + body


def parse_container(raw: bytes) -> list[Part]:
    parts: list[Part] = []
    primary: Part | None = None
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4 or struct.unpack_from("<I", raw, offset)[0] != MTK_MAGIC:
            break
        header = raw[offset : offset + MKIMG_HDR_SZ]
        name = header[8:40].split(b"\x00")[0].decode("ascii", errors="replace").lower()
        size = struct.unpack_from("<I", header, 4)[0]
        ext = struct.unpack_from("<I", header, 48)[0]
        align = struct.unpack_from("<I", header, 68)[0] if ext == MTK_EXT_MAGIC else 16
        if align == 0:
            align = 16
        data_start = offset + MKIMG_HDR_SZ
        data_end = data_start + size
        next_offset = data_end + (-data_end) % align

        p = Part(name, offset, size, align, header, raw[data_start:data_end])
        if name in ("cert1", "cert2"):
            if primary is not None:
                setattr(primary, name, p)
            p.is_primary = False
        else:
            primary = p
        parts.append(p)
        offset = next_offset
    return parts


def emit_payload_config(device_json: Path, out_h: Path) -> None:
    """Emit C/assembly/linker-safe device_config.h directly from a Loki device JSON."""
    data = json.loads(device_json.read_text(encoding="utf-8"))
    if data.get("arch", "aarch64") != "aarch64":
        sys.exit(f"Error: payload currently supports aarch64 devices only (got {data.get('arch')})")

    lk_sub = data["subpartitions"]["lk"]
    lk_syms = data["symbols"]["lk"]
    regs = data["registers"]
    keys = data["keycodes"]
    cave = data["dead_code"]["lk"]["DEADCODE_MSDC_EMMC"]
    hook = data["hooks"]["HOOK_TARGET_INIT_CALL"]

    title = f"{data['device']} ({data['soc'].split()[0]})"

    lines = [
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        f"/* AUTO-GENERATED from {device_json.name} by tools/loki-pack.py — DO NOT EDIT */",
        "#ifndef LOKI_DEVICE_CONFIG_H",
        "#define LOKI_DEVICE_CONFIG_H",
        "",
        f'#define DEVICE_TITLE                  "{title}"',
        f"#define LK_BASE                       {lk_sub['load_addr']}",
        f"#define LOKI_CAVE_ADDR                {cave['addr_start']}",
        f"#define LOKI_CAVE_SIZE                {cave['size_bytes']}",
        f"#define LK_TARGET_INIT_CALLER         {hook['target']}",
        f"#define ADDR_LK_TARGET_INIT           {hook['stock_target']}",
        "",
        "/* Display panel geometry */",
        "#define DISPLAY_WIDTH                 1080",
        "#define DISPLAY_HEIGHT                2460",
        "",
        "/* Verified stock LK functions */",
    ]

    required_syms = [
        "video_printf",
        "video_clean_screen",
        "video_set_cursor",
        "mt_disp_update",
        "detect_key",
        "get_suffix",
        "set_active",
        "set_boot_mode",
        "bio_open_by_label",
        "bio_read",
        "bio_close",
        "arch_disable_cache",
    ]
    for s in required_syms:
        if s not in lk_syms:
            sys.exit(f"Error: required LK symbol '{s}' missing in {device_json}")
        lines.append(f"#define ADDR_LK_{s.upper():<22} {lk_syms[s]['addr']}")

    lines.append("")
    lines.append("/* Verified physical MMIO registers */")
    for r in (
        "MT6789_WDT_MODE",
        "MT6789_WDT_LENGTH",
        "MT6789_WDT_RESTART",
        "MT6789_DEVAPC_APC_CON",
        "MT6789_DISP_OVL0_BASE",
        "FRAMEBUFFER_PHYS_0",
    ):
        if r not in regs:
            sys.exit(f"Error: required register '{r}' missing in {device_json}")
        lines.append(f"#define {r:<29} {regs[r]}")

    lines.append("")
    lines.append("/* Verified detect_key() keycodes */")
    for k in ("VOL_DOWN", "VOL_UP", "POWER"):
        lines.append(f"#define KEY_{k:<25} {keys[k]}")

    lines.append("")
    lines.append("#endif /* LOKI_DEVICE_CONFIG_H */")
    lines.append("")

    out_h.parent.mkdir(parents=True, exist_ok=True)
    out_h.write_text("\n".join(lines), encoding="utf-8")


def apply_fenrir_patches(parts: list[Part], unlock_el2: bool) -> None:
    for p in parts:
        if p.name not in ("lk", "bl2_ext", "aee"):
            continue
        for patch_name, (needle, repl) in SECURITY_PATCHES.items():
            pos = 0
            while True:
                idx = p.data.find(needle, pos)
                if idx == -1:
                    break
                p.data[idx : idx + len(repl)] = repl
                print(f"[+] Applied security patch {p.name}:{patch_name} @ 0x{idx:06x}")
                pos = idx + len(repl)

        if unlock_el2 and p.name == "bl2_ext":
            pos = 0
            hits = 0
            while True:
                idx = p.data.find(BL2_EXT_SPSR_EL1_NEEDLE, pos)
                if idx == -1:
                    break
                p.data[idx : idx + len(BL2_EXT_SPSR_EL2_PATCH)] = BL2_EXT_SPSR_EL2_PATCH
                print(f"[+] Patched bl2_ext SPSR drop (EL1h -> EL2h) @ 0x{idx:06x}")
                hits += 1
                pos = idx + len(BL2_EXT_SPSR_EL2_PATCH)
            if hits != 2:
                sys.exit(f"Error: expected 2 bl2_ext SPSR drop sites, patched {hits}")


def apply_cert_bypass(parts: list[Part]) -> int:
    for p in parts:
        p.update_data(bytes(p.data))

    count = 0
    for p in parts:
        if not p.cert2 or p.name.startswith("cert") or p.name == "loki_payload":
            continue
        h, d = p.hashes()
        override = build_hash_override_block(HT_OR_H_OID, h, IMG_OR_I_OID, d)
        p.cert2.update_data(override + bytes(p.cert2.data))
        count += 1
        print(f"[+] Applied cert2 hash override for subpartition: {p.name}")
    return count


def verify_output(raw: bytes, expected_payload_crc: int, expected_payload_sz: int) -> None:
    reparsed = parse_container(raw)
    for p in reparsed:
        if not p.is_primary or not p.cert2:
            continue
        cert2 = bytes(p.cert2.data)
        if len(cert2) < 2 or cert2[0] != 0xA0:
            sys.exit(f"Error: verify failed — {p.name} missing cert2 [0]-override")
        blen = cert2[1]
        block = cert2[2 : 2 + blen]
        h, d = p.hashes()
        want = HT_OR_H_OID + h + IMG_OR_I_OID + d
        if blen != len(want) or block != want:
            sys.exit(f"Error: verify failed — {p.name} cert2 hash mismatch")
        print(f"[+] Verified cert2 hash override for {p.name}: OK")

    # Verify embedded loki_payload subpartition at LOKI_SUBPART_OFFSET
    mk_magic, mk_dsize = struct.unpack_from("<II", raw, LOKI_SUBPART_OFFSET)
    mk_name = raw[LOKI_SUBPART_OFFSET + 8 : LOKI_SUBPART_OFFSET + 40].split(b"\x00")[0]
    if mk_magic != MTK_MAGIC or mk_name != b"loki_payload":
        sys.exit("Error: verify failed — loki_payload mkimg header corrupt")

    hdr_off = LOKI_SUBPART_OFFSET + MKIMG_HDR_SZ
    magic, ver, _flags, pay_off, pay_sz, _eoff, _esz, crc = struct.unpack_from("<IIIIIIII", raw, hdr_off)
    if magic != LOKI_SUBPART_MAGIC or ver != LOKI_SUBPART_VER:
        sys.exit("Error: verify failed — loki_subpart_header magic/version mismatch")
    if pay_sz != expected_payload_sz or crc != expected_payload_crc:
        sys.exit("Error: verify failed — loki_payload size/CRC header mismatch")

    embedded = raw[hdr_off + pay_off : hdr_off + pay_off + pay_sz]
    actual_crc = zlib.crc32(embedded) & 0xFFFFFFFF
    if actual_crc != expected_payload_crc:
        sys.exit("Error: verify failed — embedded payload CRC32 mismatch")
    print(f"[+] Verified loki_payload subpartition @ 0x{LOKI_SUBPART_OFFSET:06x}: {pay_sz:,} bytes, CRC32=0x{actual_crc:08x}")


def serialize_container(parts: list[Part], container_size: int) -> bytes:
    out = bytearray()
    for p in parts:
        if p.name == "loki_payload":
            if len(out) > LOKI_SUBPART_OFFSET:
                sys.exit(
                    f"Error: stock subpartitions end at 0x{len(out):x}, overlapping LOKI_SUBPART_OFFSET 0x{LOKI_SUBPART_OFFSET:x}"
                )
            out += b"\x00" * (LOKI_SUBPART_OFFSET - len(out))
        out += p.header
        out += p.data
        out += b"\x00" * ((-len(out)) % p.align)

    if len(out) > container_size:
        sys.exit(
            f"Error: packed image ({len(out):,} bytes) exceeds flash partition limit ({container_size:,} bytes)!"
        )
    out += b"\x00" * (container_size - len(out))
    return bytes(out)


def pack_image(
    device_json: Path,
    stock_lk: Path,
    cave_bin: Path,
    payload_bin: Path,
    out_img: Path,
    unlock_el2: bool,
) -> None:
    dev = json.loads(device_json.read_text(encoding="utf-8"))
    container_size = int(dev["container_size"])
    pinned_sha = dev["stock_lk_sha256"].lower()

    stock_data = stock_lk.read_bytes()
    actual_sha = sha256(stock_data).hexdigest().lower()
    if actual_sha != pinned_sha:
        sys.exit(
            f"Error: stock_lk_sha256 mismatch!\n"
            f"  Expected ({device_json.name}): {pinned_sha}\n"
            f"  Actual   ({stock_lk.name}): {actual_sha}"
        )
    print(f"[+] Verified stock LK SHA-256: {actual_sha}")

    cave_data = cave_bin.read_bytes()
    payload_data = payload_bin.read_bytes()

    lk_base = int(dev["subpartitions"]["lk"]["load_addr"], 16)
    cave_info = dev["dead_code"]["lk"]["DEADCODE_MSDC_EMMC"]
    cave_va = int(cave_info["addr_start"], 16)
    cave_max = int(cave_info["size_bytes"])
    hook_info = dev["hooks"]["HOOK_TARGET_INIT_CALL"]
    caller_va = int(hook_info["target"], 16)
    target_va = int(hook_info["stock_target"], 16)

    if len(cave_data) > cave_max:
        sys.exit(f"Error: cave payload ({len(cave_data)} B) exceeds dead-code cave ({cave_max} B)")

    max_payload = container_size - LOKI_SUBPART_OFFSET - MKIMG_HDR_SZ - LOKI_SUBPART_HDR_SZ
    if len(payload_data) > max_payload:
        sys.exit(
            f"Error: chainload payload ({len(payload_data):,} B) exceeds LK subpartition capacity ({max_payload:,} B)"
        )

    parts = parse_container(stock_data)
    lk_part = next((p for p in parts if p.name == "lk"), None)
    if not lk_part:
        sys.exit("Error: no 'lk' subpartition found in stock container")

    apply_fenrir_patches(parts, unlock_el2=unlock_el2)

    cave_off = cave_va - lk_base
    pivot_off = caller_va - lk_base

    expected_bl = encode_bl(caller_va, target_va)
    existing = bytes(lk_part.data[pivot_off : pivot_off + 4])
    if existing != expected_bl:
        sys.exit(
            f"Error: pivot site mismatch at LK+0x{pivot_off:06x} (VA 0x{caller_va:x}): "
            f"expected {expected_bl.hex()}, found {existing.hex()}"
        )
    print(f"[+] Verified stock target_init BL @ 0x{caller_va:x}")

    lk_part.data[cave_off : cave_off + len(cave_data)] = cave_data
    print(f"[+] Injected cave payload ({len(cave_data):,} / {cave_max:,} B) @ 0x{cave_va:x}")

    pivot_bl = encode_bl(caller_va, cave_va)
    lk_part.data[pivot_off : pivot_off + 4] = pivot_bl
    print(f"[+] Patched pivot hook @ 0x{caller_va:x} -> bl 0x{cave_va:x} ({pivot_bl.hex()})")

    # Build loki_payload subpartition (mkimg header + loki_subpart_header + payload)
    payload_crc = zlib.crc32(payload_data) & 0xFFFFFFFF
    subpart_hdr = struct.pack(
        "<IIIIIIII32s",
        LOKI_SUBPART_MAGIC,
        LOKI_SUBPART_VER,
        0,
        LOKI_SUBPART_HDR_SZ,
        len(payload_data),
        0,
        0,
        payload_crc,
        b"\x00" * 32,
    )
    subpart_blob = subpart_hdr + payload_data

    mkimg_hdr = bytearray(MKIMG_HDR_SZ)
    struct.pack_into("<I", mkimg_hdr, 0, MTK_MAGIC)
    struct.pack_into("<I", mkimg_hdr, 4, len(subpart_blob))
    mkimg_hdr[8 : 8 + len("loki_payload")] = b"loki_payload"
    struct.pack_into("<I", mkimg_hdr, 48, MTK_EXT_MAGIC)
    struct.pack_into("<II", mkimg_hdr, 52, MKIMG_HDR_SZ, 1)
    struct.pack_into("<I", mkimg_hdr, 68, 16)

    loki_part = Part("loki_payload", LOKI_SUBPART_OFFSET, len(subpart_blob), 16, mkimg_hdr, subpart_blob)
    loki_part.is_primary = False
    parts.append(loki_part)

    bypassed = apply_cert_bypass(parts)
    print(f"[+] Applied cert2 hash overrides on {bypassed} primary subpartitions")

    out_bytes = serialize_container(parts, container_size)
    verify_output(out_bytes, payload_crc, len(payload_data))

    out_img.parent.mkdir(parents=True, exist_ok=True)
    out_img.write_bytes(out_bytes)
    out_sha = sha256(out_bytes).hexdigest()
    print(f"[+] Wrote verified image: {out_img} ({len(out_bytes):,} bytes, SHA-256: {out_sha})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Loki composite lk.img packer & config generator")
    parser.add_argument("--emit-config", type=Path, help="Emit device_config.h from device JSON")
    parser.add_argument("--device", type=Path, help="Path to verified device JSON (e.g. devices/mt6789/advan_x1_v5.json)")
    parser.add_argument("--lk", type=Path, help="Path to pristine stock lk.img")
    parser.add_argument("--cave", type=Path, help="Path to compiled loki_cave.bin")
    parser.add_argument("--payload", type=Path, help="Path to standalone chainload payload (e.g. u-boot.bin)")
    parser.add_argument("--out", required=True, type=Path, help="Output file path")
    parser.add_argument("--unlock-el2", action="store_true", help="Patch bl2_ext SPSR drop from EL1h to EL2h (KVM)")
    args = parser.parse_args()

    if args.emit_config:
        emit_payload_config(args.emit_config, args.out)
        return

    for req in ("device", "lk", "cave", "payload"):
        if not getattr(args, req):
            sys.exit(f"Error: --{req} is required when packing lk_loki.img")

    pack_image(
        device_json=args.device,
        stock_lk=args.lk,
        cave_bin=args.cave,
        payload_bin=args.payload,
        out_img=args.out,
        unlock_el2=args.unlock_el2,
    )


if __name__ == "__main__":
    main()
