# loki

> **MediaTek Little Kernel (LK), BL2_EXT & AEE Reverse-Engineering & Symbol Map Database**

`loki` is an open-source reverse-engineering framework and symbol database for MediaTek bootchains. It maps partition layouts, execution levels, and stock function addresses across the entire composite `lk.img` container (`lk`, `bl2_ext`, `aee`, `dtb`), providing discovery tools and recipes across **PyGhidra**, **Radare2**, **Rizin**, and **Capstone**.

---

## 1. Supported SoCs & Device Mappings

| SoC | Device | Baseline | Container SHA-256 | Mapping File |
|---|---|---|---|---|
| **MediaTek MT6789** (Helio G99 / MT8781) | ADVAN X1 | `v5` (Retail) | `a11516b640cfdadfc616dcca9db0160ad72dd473a035830b08ed5802883ae834` | [`devices/mt6789/advan_x1_v5.json`](devices/mt6789/advan_x1_v5.json) |

---

## 2. Partition Architecture (`lk.img`)

The MediaTek `lk` partition (4 MiB) is a multi-image container containing discrete sub-images:

```
+--------------------------------------------------------------------------------------------------+
|                              COMPOSITE lk.img PARTITION (4 MiB Flash)                            |
+--------------------------------------------------------------------------------------------------+
| Partition Offset | Sub-Image Name | Size (Bytes) | Domain / Privilege   | Load Virtual Address   |
+------------------+----------------+--------------+----------------------+------------------------+
| 0x000000         | lk             | 667,424 B    | BL33 / Non-Secure EL1| 0xFFFF000050F00000     |
| 0x0A3120         | cert1 + cert2  | 2,691 B      | ASN.1 DER Signature  | N/A                    |
| 0x0A3FB0         | bl2_ext        | 527,904 B    | BL2 / Secure EL3     | 0xFFFF000062F00000     |
| 0x124FD0         | cert1 + cert2  | 2,715 B      | ASN.1 DER Signature  | N/A                    |
| 0x125E80         | aee            | 741,608 B    | Exception Engine/EL1 | 0xFFFF000063F00000     |
| 0x1DB170         | cert1 + cert2  | 2,715 B      | ASN.1 DER Signature  | N/A                    |
| 0x1DC020         | lk_main_dtb    | 189,175 B    | Base Device Tree     | FDT Staging in DRAM    |
| 0x20A520         | cert1 + cert2  | 2,691 B      | ASN.1 DER Signature  | N/A                    |
| 0x20B3A6..400000 | [Unallocated]  | 2,051,162 B  | Trailing flash space | Unused                 |
+------------------+----------------+--------------+----------------------+------------------------+
```

---

## 3. Stock Bootchain Lifecycle Overview

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

## 4. Discovery Tooling Suite

* **`make verify` / `tools/verify.py`**: Automated schema, C header, dead-code, and binary assertion suite.
* **`make proof` / `tools/proof/build_proof.py`**: Compiles freestanding ARM64 proof hook and tests zero-region placement.
* **`make deadcode` / `tools/capstone/scan_deadcode.py`**: Scans hardware strapping selectors and verifies dead code cave isolation.
* **`tools/unpack.py`**: Extracts all discrete sub-images and signatures from `lk.img`.
* **`tools/capstone/scan_lk.py`**: Scans raw LK ARM64 binaries for MMU disable jumps, SMC boot trampolines, WDT keys, and string anchors.
* **`tools/capstone/scan_bl2_ext.py`**: Scans raw BL2_EXT binaries for SPSR privilege drop sites and memory reservation pools.
* **`tools/pyghidra/analyze_lk.py`**: Headless Ghidra decompilation and cross-reference crawler.
* **`tools/radare2/lk_map.r2`**: Interactive radare2 flags, functions, and analysis macros.
* **`tools/rizin/lk_map.rz`**: Interactive rizin analysis script.

---

## 5. Code Placement Strategies: Zero-Regions vs Dead-Code Caves

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

## 6. Documentation

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
