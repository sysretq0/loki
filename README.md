# loki

> **MediaTek Little Kernel (LK), BL2_EXT & AEE Reverse-Engineering & Symbol Map Database**

`loki` is an open-source reverse-engineering framework and symbol database for MediaTek bootchains. It maps partition layouts, execution levels, and stock function addresses across the entire composite `lk.img` container (`lk`, `bl2_ext`, `aee`, `dtb`), providing discovery tools and recipes across **PyGhidra**, **Radare2**, **Rizin**, and **Capstone**.

---

## 1. Supported SoCs & Device Mappings

| SoC | Device | Baseline | Container SHA-256 | Mapping File |
|---|---|---|---|---|
| **MediaTek MT6789** (Helio G99 / MT8781) | ADVAN X1 | `v5` (Retail) | `a11516b640cfdadfc616dcca9db0160ad72dd473a035830b08ed5802883ae834` | [`devices/mt6789/advan_x1_v5.json`](devices/mt6789/advan_x1_v5.json) |

---

## 2. Quickstart & Unified CLI (`./loki`)

`loki` provides a unified command runner `./loki` to inspect, unpack, scaffold, and verify device profiles:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. View supported devices
./loki devices

# 3. Scaffold a new device profile from stock firmware
./loki init <device_codename> <soc_name> /path/to/stock/lk.img

# 4. Run the full verification suite
./loki verify
# Or via Makefile:
make verify FW=/path/to/stock/lk.img
```

### CLI Subcommands Reference

| Subcommand | Purpose | Usage Example |
|---|---|---|
| `devices` | List all mapped devices and SoC architectures | `./loki devices` |
| `init` | Bootstrap new device `.json` and `.h` from `lk.img` | `./loki init advan_x1 mt6789 /path/to/lk.img` |
| `unpack` | Extract raw subpartitions from composite `lk.img` | `./loki unpack /path/to/lk.img extracted/` |
| `scan` | Scan raw `lk.bin` for MMU, SMC, and anchor points | `./loki scan extracted/00_lk.bin` |
| `scan-bl2` | Scan `bl2_ext.bin` for SPSR drops & memory pools | `./loki scan-bl2 extracted/03_bl2_ext.bin` |
| `deadcode` | Scan hardware strapping & dead-code caves | `./loki deadcode extracted/00_lk.bin` |
| `verify` | Validate schemas, C headers, and binary assertions | `./loki verify [device.json] [-f lk.img]` |
| `gen-header` | Auto-generate C header (`.h`) from device `.json` | `./loki gen-header devices/mt6789/advan_x1_v5.json` |
| `proof` | Build freestanding proof hook & verify placement | `./loki proof [extracted/00_lk.bin]` |

> [!TIP]
> You can point `loki` and `make` to your local firmware dump using the `LOKI_FIRMWARE_IMG` environment variable or the `FW=` parameter:
> ```bash
> export LOKI_FIRMWARE_IMG=/path/to/stock/lk.img
> make verify
> ```

---

## 3. Partition Architecture (`lk.img`)

The MediaTek `lk` partition (4 MiB) is an `mkimg` multi-image container containing discrete sub-images. Every sub-image (including certificates) is preceded by a 512-byte `mkimg` header (`magic: 0x58881688`):

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                        COMPOSITE lk.img PARTITION (4 MiB Flash)                                       |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| Container Offset  | Sub-Image Name | Payload Size | Component Type    | Domain / Privilege   | Load Address (VA)  |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| 0x000000..0x000200| lk (header)    | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x000200..0x0A3120| lk (payload)   | 667,424 B    | Little Kernel 2   | BL33 / Non-Secure EL1| 0xFFFF000050F00000 |
| 0x0A3120..0x0A3FB0| cert1 + cert2  | 2,704 B      | Headers + ASN.1   | DER Signature Blobs  | N/A                |
| 0x0A3FB0..0x0A41B0| bl2_ext (hdr)  | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x0A41B0..0x124FD0| bl2_ext (pay)  | 527,904 B    | Bootloader Ext.   | BL2 / Secure EL3     | 0xFFFF000062F00000 |
| 0x124FD0..0x125E80| cert1 + cert2  | 3,760 B      | Headers + ASN.1   | DER Signature Blobs  | N/A                |
| 0x125E80..0x126080| aee (header)   | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x126080..0x1DB168| aee (payload)  | 741,608 B    | Exception Engine  | Exception Core / EL1 | 0xFFFF000063F00000 |
| 0x1DB168..0x1DC020| cert1 + cert2  | 3,768 B      | Headers + ASN.1   | DER Signature Blobs  | N/A                |
| 0x1DC020..0x1DC220| dtb (header)   | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x1DC220..0x20A517| lk_main_dtb    | 189,175 B    | Device Tree Blob  | Flattened Device Tree| Staged in DRAM     |
| 0x20A517..0x20B3A6| cert1 + cert2  | 3,727 B      | Headers + ASN.1   | DER Signature Blobs  | N/A                |
| 0x20B3A6..0x400000| [Unallocated]  | 2,051,162 B  | Trailing Free     | Pure 0x00 Space      | Unallocated (1.96M)|
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
```

---

## 4. Stock Bootchain Lifecycle Overview

```
[ Mask ROM BROM ]
       │
       ▼ (Loads to SRAM 0x00201000)
[ Preloader (BL2, EL3) ]
       │
       │ 1. Inits PMIC & Calibrates LPDDR4X DRAM
       │ 2. Stages Sub-Image 1 (bl2_ext) into DRAM
       ▼
[ bl2_ext (Secure EL3) @ 0xFFFF000062F00000 ]
       │
       │ 1. Allocates "vm-BL33-reserved" (0x40000000) -> Copies 'lk'
       │ 2. Allocates "vm-BL31-reserved" (0x48200000) -> Copies 'atf'
       │ 3. Sets SPSR drop to Non-Secure EL1h (0x3c5)
       │ 4. Branches to ATF BL31
       ▼
[ ARM Trusted Firmware (BL31, EL3) ]
       │
       │ Configures PSCI & drops privilege via SPSR
       ▼
[ Little Kernel (BL33, Non-Secure EL1) @ 0xFFFF000050F00000 ]
       │
       │ 1. Initializes MMU (TTBR0/TTBR1), heap, generic timer, UART0
       │ 2. Spawns bootstrap2 thread -> Inits DSI Display & UFS Storage
       │ 3. Evaluates hardware keys & reboot reasons
       │ 4. Decompresses kernel image (0x50F0BD58) & appends bootargs
       │ 5. Cleans caches, disables MMU, executes SMC 0xC2000115
       ▼
[ Linux Kernel (Non-Secure EL1) ]
```

---

## 5. Tooling & Discovery Suite

`loki` offers three interchangeable execution layers: the high-level `./loki` CLI, standard `make` targets, and raw Python scripts:

| Workflow Step | Unified CLI | Make Target | Standalone Script |
|---|---|---|---|
| **Full Validation** | `./loki verify` | `make verify` | `python3 tools/verify.py` |
| **Proof Hook Placement** | `./loki proof` | `make proof` | `python3 tools/proof/build_proof.py` |
| **Dead-Code Analysis** | `./loki deadcode` | `make deadcode` | `python3 tools/capstone/scan_deadcode.py` |
| **Device Scaffolding** | `./loki init <name> <soc> <img\>` | — | `python3 tools/init_device.py` |
| **Header Generation** | `./loki gen-header <json\>` | `make gen-header DEVICE=...` | `python3 tools/gen_header.py` |
| **Container Unpacking** | `./loki unpack <img\>` | — | `python3 tools/unpack.py` |
| **LK Symbol Scanning** | `./loki scan <bin\>` | — | `python3 tools/capstone/scan_lk.py` |
| **BL2_EXT Scanning** | `./loki scan-bl2 <bin\>` | — | `python3 tools/capstone/scan_bl2_ext.py` |
| **Interactive RE (r2)** | — | — | `r2 -i tools/radare2/lk_map.r2 extracted/00_lk.bin` |
| **Interactive RE (rizin)** | — | — | `rizin -i tools/rizin/lk_map.rz extracted/00_lk.bin` |
| **Headless Decompilation** | — | — | `python3 tools/pyghidra/analyze_lk.py extracted/00_lk.bin` |

---

## 6. Code Placement Strategies: Zero-Regions vs Dead-Code Caves

`loki` categorizes executable code placement into two distinct methods depending on payload size and build requirements:

1. **Pristine Zero-Filled Padding Regions (`.text` RX):**
   * Contiguous linker alignment padding filled with pure `0x00` bytes (`ZERO_REGION_1`: 3,272 bytes at `0xFFFF000050F00338`).
   * Overwrites zero existing instructions; ideal for small, non-invasive trampolines.
2. **Hardware-Specific Dead-Code Caves (`.text` RX):**
   * Contiguous driver subtrees unreached due to hardware strapping (`DEADCODE_MSDC_EMMC`: **27,456 bytes / 26.8 KiB** at `0xFFFF000050F1F2A0`).
   * On UFS-booted hardware (e.g. ADVAN X1), strapping bit 10 routes exclusively to `ufs_init`, leaving the entire eMMC driver completely unexecuted at runtime.
   * Ideal for large multi-stage payloads, memory dumpers, and custom chainloader shims.
3. **Partition Flash Free Space:**
   * Trailing space from `0x20B3A6` to `0x400000` (2,051,162 bytes / 1.956 MiB pure `0x00`) available for standalone secondary payloads.

See [Safe Hook Entry Points & Zero-Region Catalog](docs/HOOK_ENTRY_POINTS.md) and [Hardware-Specific Dead Code Map](docs/DEAD_CODE_MAP.md) for details.

---

## 7. Documentation

* [Hardware-Specific Dead Code Map](docs/DEAD_CODE_MAP.md): Analysis of unreached driver caves, strapping selectors, and large payload placement.
* [Safe Hook Entry Points & Zero-Region Catalog](docs/HOOK_ENTRY_POINTS.md): Comprehensive catalog of 17 safe hook sites and zero-padding placement.
* [Bootchain Lifecycle Deep-Dive](docs/BOOTCHAIN_LIFECYCLE.md): Full analysis of BROM, Preloader, BL2_EXT, ATF, LK, and Linux Kernel handoff.
* [Little Kernel (LK) Function Map](docs/LK_FUNCTION_MAP.md): Detailed function reference for the ADVAN X1 v5 baseline.
* [BL2_EXT & AEE Map](docs/BL2_EXT_AND_AEE_MAP.md): Comprehensive map of the EL3 bootloader extension and exception engine.
* [Reverse-Engineering Guide](docs/REVERSE_ENGINEERING_GUIDE.md): Step-by-step tutorial on discovering symbols using PyGhidra, r2, rizin, and Capstone.
* [Contributing Guide](CONTRIBUTING.md): Instructions for mapping your device and submitting a Pull Request.

---

## License

GPL-3.0-or-later
