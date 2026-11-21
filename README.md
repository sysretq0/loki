# loki

> **MediaTek Complete Bootchain Mapping, Reverse-Engineering & Symbol Database (BROM → Preloader → BL2_EXT → ATF BL31 → LK BL33 → Device Tree Pipeline → OS Handoff)**

`loki` is an open-source reverse-engineering framework, symbol database, and architectural mapping tool for MediaTek bootchains. It maps partition layouts, execution privilege levels (EL3/EL1), stock function addresses, hardware strapping selectors, and dynamic firmware pipelines across composite containers (`preloader.img`, `tee.img`, `lk.img`, `dtbo.img`, and `vendor_boot.img`), providing discovery tools and recipes across **PyGhidra**, **Radare2**, **Rizin**, and **Capstone**.

---

## 1. Supported SoCs & Device Mappings

| SoC | Device | Baseline | Container SHA-256 (lk.img) | TEE SHA-256 (tee.img) | Preloader SHA-256 (preloader.img) | Base DTB SHA-256 (lk/vendor_boot) | Mapping File |
|---|---|---|---|---|---|---|---|
| **MediaTek MT6789** (Helio G99 / MT8781) | ADVAN X1 | `v5` (Retail) | `a11516b640cfdadfc616dcca9db0160ad72dd473a035830b08ed5802883ae834` | `0a961a9940f01090005bf5ce1cd33d58c835f8d0925ba28bd187b114c582db44` | `f1cedb6912be99cbedc2fc49b0033e6067dda08fc836b2d3900e634e71b35d50` | `2285a2859d1e3c8a375b752f687b16b4e494ae41d0211a507bb99d131524e363` | [`devices/mt6789/advan_x1_v5.json`](devices/mt6789/advan_x1_v5.json) |

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
| `scan-atf` | Scan `atf.bin` or `tee.img` for VBAR_EL3, PSCI & SiP SMCs | `./loki scan-atf /path/to/tee.img` |
| `scan-pl` | Scan `preloader.img` for GFH, entry & USBDL loop | `./loki scan-pl /path/to/preloader.img` |
| `deadcode` | Scan hardware strapping & dead-code caves | `./loki deadcode extracted/00_lk.bin` |
| `verify` | Validate schemas, C headers, and binary assertions | `./loki verify [device.json] [-f lk.img]` |
| `gen-header` | Auto-generate C header (`.h`) from device `.json` | `./loki gen-header devices/mt6789/advan_x1_v5.json` |
| `proof` | Build freestanding proof hook & verify placement | `./loki proof [extracted/00_lk.bin]` |
| `pack` | Build Stage-1 cave and pack `lk_loki.img` with embedded subpartition (`0x210000`) | `./loki pack devices/mt6789/advan_x1_v5.json --lk lk.img --payload uboot/build/u-boot.bin` |

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

### 3.1 TEE Partition Architecture (`tee.img`)

The MediaTek `tee` partition contains ARM Trusted Firmware (BL31) and the Secure OS (BL32 / Trustonic Kinibi), packaged with standard `mkimg` headers (`magic: 0x58881688`):

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                        COMPOSITE tee.img PARTITION (6 MiB Flash)                                      |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| Container Offset  | Sub-Image Name | Payload Size | Component Type    | Domain / Privilege   | Load Address (Phys)|
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| 0x000000..0x000200| atf (header)   | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x000200..0x030758| atf (payload)  | 197,976 B    | TF-A v2.4 (BL31)  | Secure Monitor / EL3 | 0x0000000048200000 |
| 0x030760..0x0315F0| cert1 + cert2  | 3,728 B      | Headers + ASN.1   | DER Signature Blobs  | N/A                |
| 0x0315F0..0x0317F0| tee (header)   | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x0317F0..0x0BABF0| tee (payload)  | 562,176 B    | Kinibi (<t-base)  | Secure OS (BL32)/EL1 | 0x0000000070000000 |
| 0x0BABF0..0x0BB878| cert1 + cert2  | 3,728 B      | Headers + ASN.1   | DER Signature Blobs  | N/A                |
| 0x0BB878..0x600000| [Unallocated]  | 5,522,826 B  | Trailing Free     | Pure 0x00 Space      | Unallocated (5.27M)|
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
```

> [!NOTE] Slot Partition Geometry Asymmetry
> On the MT6789 retail UFS partition table (ADVAN X1), the TEE partition sizes differ between A/B slots:
> - **Slot `_b` (`tee_b`)**: **6 MiB** (`0x600000` / 6,291,456 B) $\rightarrow$ trailing unallocated space: `5,522,826 B` (**~5.27 MiB**)
> - **Slot `_a` (`tee_a`)**: **5 MiB** (`0x500000` / 5,242,880 B) $\rightarrow$ trailing unallocated space: `4,474,250 B` (**~4.27 MiB**, exactly **1 MiB less**)
> Any custom payload or intermediate chainloader staged into trailing TEE partition space must fit within the strict 5 MiB bound (`0x500000`) if deployed to slot `_a`.

### 3.2 Preloader Boot Partition Architecture (`preloader.img` / UFS Boot LUNs `sda` & `sdb`)

The MediaTek Preloader executes in internal SRAM (`0x00201000`) at AArch32 Secure EL3. On UFS devices, it is flashed to the hardware boot LUNs (`/dev/block/sda` and `/dev/block/sdb`, 4 MiB each) packaged inside a `COMBO_BOOT` wrapper and GFH (General File Header):

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                    PRELOADER BOOT LUN PARTITION (4 MiB Flash / sda & sdb)                             |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| Container Offset  | Sub-Image Name | Payload Size | Component Type    | Domain / Privilege   | Load Address (SRAM)|
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| 0x000000..0x001000| COMBO_BOOT pad | 4,096 B      | MTK Wrapper Pad   | Container Header     | N/A                |
| 0x001000..0x0010F0| GFH Header     | 240 B        | MTK FILE_INFO     | GFH Metadata (0xF0)  | N/A                |
| 0x0010F0..0x059900| preloader bin  | 362,512 B    | Preloader Core    | BL2 / Secure EL3 SVC | 0x00201000 (A32)   |
| 0x059900..0x059F6C| signature      | 1,644 B      | MTK Sig Block     | RSA-2048 / SHA-256   | N/A                |
| 0x059F6C..0x400000| [Unallocated]  | 3,825,812 B  | Trailing Free     | Pure 0x00 Space      | Unallocated (3.65M)|
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
```

> [!NOTE] Internal SRAM Execution & Entry
> The GFH header declares `load_addr = 0x00200F10` and `jump_offset = 0xF0`. The execution base in internal SRAM is exactly `0x00200F10 + 0xF0 = 0x00201000`. The entry code zeroes `r0` through `lr`, queries `MIDR` for Cortex-A55 (`0xD03`/`0xD04`), sets SVC mode (`0xD3`), initializes clocks/PMIC/EMI, and handles the USB download protocol before loading BL2_EXT/ATF.

### 3.3 Device Tree Pipeline Architecture (`lk_main_dtb`, `dtbo.img`, `vendor_boot.img`)

MediaTek Little Kernel executes a multi-stage Device Tree pipeline that merges, mutates, and appends hardware reservations before handing execution to the kernel:

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                        DEVICE TREE MUTATION & HANDOFF PIPELINE                                        |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| Container / Stage | Component Name | Payload Size | Verification Hash | Operation in LK      | Memory Target (PA) |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| lk.img / subpart 3| lk_main_dtb    | 189,175 B    | SHA-256: 2285a285 | Staged in DRAM       | 0x47C80000         |
| vendor_boot.img   | dt_table[0]    | 189,175 B    | SHA-256: 2285a285 | 100% Binary Identical| GKI fallback       |
| dtbo.img (flash)  | dtbo_entry0    | 52,589 B     | SHA-256: 91d75534 | Applied via overlay  | Merged in DRAM     |
| Memory Merged FDT | post-overlay   | 241,764 B    | N/A               | Peripheral inits     | DRAM buffer        |
| LK set_fdt Hooks  | dynamic patch  | N/A          | N/A               | LCM, UFS mmc0, AVB   | DRAM buffer        |
| MBLOCK Injection  | reserved-nodes | 31 regions   | N/A               | /reserved-memory     | DRAM buffer        |
| Final Live FDT    | runtime handoff| 253,152 B    | Matches /sys/fdt  | Kernel DTB pointer   | 0x47C80000         |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
```

> [!TIP] Binary Identity Proof & Detailed Analysis
> For the complete 6-stage lifecycle breakdown and the catalog of all 31 dynamically generated `mblock` physical memory reservations, see [Device Tree Pipeline Architecture](docs/DEVICE_TREE_PIPELINE.md).

---

## 4. Stock Bootchain Lifecycle Overview

```
[ Mask ROM BROM ]
       │
       ▼ (Loads to SRAM 0x00201000)
[ Preloader (BL2, EL3) ]
       │
       │ 1. Inits PMIC & Calibrates LPDDR4X DRAM
       │ 2. Sets up early mblock allocations (dramc, emi_mbist, pl-drambuf)
       │ 3. Stages Sub-Image 1 (bl2_ext) into DRAM @ 0x62F00000
       ▼
[ bl2_ext (Secure EL3) @ 0xFFFF000062F00000 ]
       │
       │ 1. Allocates "vm-BL33-reserved" (0x40000000) -> Copies 'lk'
       │ 2. Allocates "vm-BL31-reserved" (0x48200000) -> Copies 'atf'
       │ 3. Sets SPSR drop to Non-Secure EL1h (0x3c5)
       │ 4. Branches to ATF BL31
       ▼
[ ARM Trusted Firmware (BL31, EL3) @ 0x48200000 ]
       │
       │ 1. Registers Secure Monitor & installs VBAR_EL3 @ 0x4821F800
       │ 2. Registers PSCI and 64 MediaTek SiP SMC services
       │ 3. Drops privilege via SPSR to Non-Secure EL1 Little Kernel
       ▼
[ Little Kernel (BL33, Non-Secure EL1) @ 0xFFFF000050F00000 ]
       │
       │ 1. Initializes MMU (TTBR0/TTBR1), heap, generic timer, UART0
       │ 2. Spawns bootstrap2 thread -> Inits DSI Display (0xFE007000) & UFS Storage
       │ 3. Evaluates hardware keys & reboot reasons
       │ 4. Decompresses kernel image (0x50F0BD58) to 0x40000000
       │ 5. Executes Device Tree Pipeline (lk_main_dtb + dtbo -> 31 mblocks -> 0x47C80000)
       │ 6. Cleans caches, disables MMU, executes SMC 0xC2000115 (MTK_SIP_KERNEL_BOOT_AARCH64)
       ▼
[ Linux Kernel (Non-Secure EL1) ]
       ├── PC      : 0x40000000 (Decompressed 64-bit kernel)
       ├── Ramdisk : 0x66F00000 (52,727,689 B)
       └── DTB     : 0x47C80000 (253,152 B merged & mutated FDT)
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
| **Header & Script Sync** | `./loki gen-header <json\> [--all]` | `make gen-header DEVICE=...` | `python3 tools/gen_header.py <json\> --all` |
| **Container Unpacking** | `./loki unpack <img\>` | — | `python3 tools/unpack.py` |
| **LK Symbol Scanning** | `./loki scan <bin\>` | — | `python3 tools/capstone/scan_lk.py` |
| **BL2_EXT Scanning** | `./loki scan-bl2 <bin\>` | — | `python3 tools/capstone/scan_bl2_ext.py` |
| **ATF / BL31 Scanning** | `./loki scan-atf <img\>` | `make scan-atf` | `python3 tools/capstone/scan_atf.py` |
| **Preloader Scanning** | `./loki scan-pl <img\>` | `make scan-pl` | `python3 tools/capstone/scan_preloader.py` |
| **Interactive RE (r2)** | — | — | `r2 -i tools/radare2/lk_map.r2 extracted/00_lk.bin` |
| **Preloader RE (r2)** | — | — | `r2 -i tools/radare2/pl_map.r2 -B 0x00201000 extracted/00_preloader.bin` |
| **Interactive RE (rizin)** | — | — | `rizin -i tools/rizin/lk_map.rz extracted/00_lk.bin` |
| **Preloader RE (rizin)** | — | — | `rizin -i tools/rizin/pl_map.rz -m 0x00201000 extracted/00_preloader.bin` |
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

* [Device Tree Pipeline Architecture](docs/DEVICE_TREE_PIPELINE.md): In-depth analysis of base DTB, DTBO overlay, LK dynamic mutations, and 31 MBLOCK physical memory reservations.
* [Hardware-Specific Dead Code Map](docs/DEAD_CODE_MAP.md): Analysis of unreached driver caves, strapping selectors, and large payload placement.
* [Safe Hook Entry Points & Zero-Region Catalog](docs/HOOK_ENTRY_POINTS.md): Comprehensive catalog of 17 safe hook sites and zero-padding placement.
* [Bootchain Lifecycle Deep-Dive](docs/BOOTCHAIN_LIFECYCLE.md): Full analysis of BROM, Preloader, BL2_EXT, ATF, LK, and Linux Kernel handoff.
* [Little Kernel (LK) Function Map](docs/LK_FUNCTION_MAP.md): Detailed function reference for the ADVAN X1 v5 baseline.
* [BL2_EXT & AEE Map](docs/BL2_EXT_AND_AEE_MAP.md): Comprehensive map of the EL3 bootloader extension and exception engine.
* [Reverse-Engineering Guide](docs/REVERSE_ENGINEERING_GUIDE.md): Step-by-step tutorial on discovering symbols using PyGhidra, r2, rizin, and Capstone.
* [Contributing Guide](CONTRIBUTING.md): Instructions for mapping your device and submitting a Pull Request.

---

## Submodules

| Path | Upstream / Role | License |
|---|---|---|
| `uboot/` | [`sysretq0/advan-x1-uboot`](https://github.com/sysretq0/advan-x1-uboot) — Clean patch-series port of upstream U-Boot for Advan X1 (MT6789) | GPL-2.0-only |
| `mainline/` | [`sysretq0/advan-x1-mainline`](https://github.com/sysretq0/advan-x1-mainline) — Clean patch-series mainline Linux port for Advan X1 (MT6789) | GPL-2.0-only |

---

## Credits & Acknowledgments

* **Roger Ortiz (`R0rt1z2`)** — [`liblk`](https://github.com/R0rt1z2/liblk) / **Fenrir** (GPL-3.0): MediaTek `cert2` ASN.1 context `[0]` hash-override OIDs/format and security policy bypass patterns used in [`tools/loki-pack.py`](tools/loki-pack.py).

---

## License

GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See [LICENSE](LICENSE) for full terms.
