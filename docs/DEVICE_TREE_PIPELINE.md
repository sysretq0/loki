# MediaTek MT6789 Device Tree Pipeline Architecture

> **Complete Lifecycle Mapping: Base DTB, DTBO Overlay, Dynamic LK Mutations, MBLOCK Reservations, and OS Handoff**

This document provides the definitive architectural map of the **Device Tree (FDT) Pipeline** across the MediaTek MT6789 (Helio G99 / MT8781) bootchain, based on physical binary analysis, live `/proc/pl_lk` ring-buffer tracing, and decompiled device trees (`.dts`) on the ADVAN X1 retail baseline (`v5`).

---

## 1. Executive Summary & Pipeline Overview

MediaTek devices do not hand off a static device tree from disk directly to the Linux kernel. Instead, the Flattened Device Tree undergoes a multi-stage mutation pipeline within **Little Kernel (BL33)** before being passed to the kernel at `0x47C80000`:

```
+-------------------------------------------------------------------------------------------------------------------+
|                                        MT6789 DEVICE TREE LIFECYCLE PIPELINE                                      |
+-------------------------------------------------------------------------------------------------------------------+
|                                                                                                                   |
|  [ lk.img: lk_main_dtb ] (189,175 B)        [ vendor_boot.img: dt_table[0] ] (189,175 B)                         |
|         │                                                     │                                                   |
|         │ SHA-256: 2285a285... (100% IDENTICAL)               │ (Fallback/GKI standard reference)                 |
|         ▼                                                     ▼                                                   |
|  [ 1. LK Base DTB Loader ] ──> Staged in DRAM @ 0x47C80000 (189,175 B, compatible = "mediatek,MT6789")         |
|         │                                                                                                         |
|         ▼                                                                                                         |
|  [ 2. DTBO Overlay Application ] <── Reads /dev/block/by-name/dtbo (Entry 0: 52,589 B, SHA: 91d75534...)         |
|         │                           platform_load_device_tree() merges overlay                                   |
|         ▼                                                                                                         |
|  [ In-Memory Merged FDT ] ──> Expanded size: 241,764 B                                                            |
|         │                                                                                                         |
|         ▼                                                                                                         |
|  [ 3. LK Peripheral Inits ] ──> mt_gpio_set_default(fdt), i2c_hw_init(fdt), disp_init(fdt), leds_init(fdt)      |
|         │                                                                                                         |
|         ▼                                                                                                         |
|  [ 4. Dynamic Mutation Chain (set_fdt hooks) ]                                                                    |
|         ├── disp_lcm_fill_lcm_dts_phandle : Injects active panel parameters & LCM timings                         |
|         ├── update_mmc_dts              : Disables mmc0 when hardware strapping detects UFS 2.2 boot              |
|         ├── set_fdt_avb_cmdline         : Injects AVB 2.0 flags and dm-verity state into /chosen/bootargs        |
|         ├── platform_fdt_set_chipid     : Injects SoC chip ID (MT6789) & hardware revision                       |
|         └── platform_atag_devinfo_data  : Injects factory calibration fuses & devinfo                            |
|         │                                                                                                         |
|         ▼                                                                                                         |
|  [ 5. MBLOCK Reservation Injection ] ──> mblock_fdt_reserved_append() appends 31 reserved-memory nodes            |
|         │                                 Final FDT Size: 253,152 B                                               |
|         ▼                                                                                                         |
|  [ 6. OS Handoff: boot_linux_fdt() ]                                                                              |
|         ├── Kernel PC   : 0x40000000 (Decompressed 64-bit Image)                                                  |
|         ├── Ramdisk Base: 0x66F00000 (52,727,689 B)                                                               |
|         └── FDT Base    : 0x47C80000 (253,152 B, exactly matching live /sys/firmware/fdt)                        |
|                                                                                                                   |
+-------------------------------------------------------------------------------------------------------------------+
```

---

## 2. Base Device Tree Identity Proof

In stock MediaTek builds, the base device tree is embedded in two independent firmware containers:
1. **`lk.img` Subpartition 3 (`lk_main_dtb`)**:
   - Offset in container: `0x1DC020` (512-byte `mkimg` header)
   - Payload offset: `0x1DC220`
   - Payload size: `189,175` bytes (`0x2E2F7`)
2. **`vendor_boot.img` DTB Table Entry 0**:
   - Container offset: `0x18FB000` (Android `DT_TABLE_MAGIC`: `0xd7b7ab1e`)
   - Entry 0 payload offset: `0x18FB040`
   - Payload size: `189,175` bytes

### Binary Hash Comparison
| Firmware File | Container Type | Extraction Method | Extracted Size | SHA-256 Checksum |
|---|---|---|---|---|
| `lk.img` | MTK `mkimg` | `subpartitions.dtb` payload | 189,175 B | `2285a2859d1e3c8a375b752f687b16b4e494ae41d0211a507bb99d131524e363` |
| `vendor_boot.img` | Android Vendor Boot v4 | DT Table Entry 0 | 189,175 B | `2285a2859d1e3c8a375b752f687b16b4e494ae41d0211a507bb99d131524e363` |

> [!IMPORTANT]
> The base device trees are **100% binary identical**. MediaTek Little Kernel uses the in-LK `lk_main_dtb` during boot, while Android GKI uses the `vendor_boot` DTB table for GKI compliance.

---

## 3. The 6-Stage DTB Lifecycle

### Stage 1: Preloader & Early Memory Reservations
During BL2 Preloader execution (`0x00201000` internal SRAM), initial memory regions are staked out via the `mblock` allocator:
- `dramc-rk0` (`0x13FFFF000`, 4 KiB) & `dramc-rk1` (`0x23FFFF000`, 4 KiB): DRAM calibration tables.
- `emi_mbist_buf` (`0x7FFFF000`, 4 KiB): Memory BIST scratchpad.
- `system_bl2-ext` (`0x62F00000`, 32 MiB): Bootloader Extension staging buffer.
- `BL31-reserved` (`0x48200000`, 2 MiB): ARM Trusted Firmware runtime.
- `tee-reserved` (`0x70000000`, 108 MiB): Trustonic Kinibi TEE-OS runtime.

### Stage 2: Base DTB Load into DRAM
When Little Kernel (BL33) initializes, it locates `lk_main_dtb` from its own partition container:
```text
lk_main_dtb image name found
mkimg hdr detected (189175)
img_auth_required = 0
Load 'lk_b' partition to 0x0xffff000063028010 (189175 bytes in 3 ms)
```

### Stage 3: DTBO Overlay Application
Next, Little Kernel loads the `dtbo` partition (Android DTBO table entry 0):
```text
DT hdr detected (52653)
img_auth_required = 0
Load 'dtbo_b' partition to 0x0xffff0000630a9f88 (52653 bytes in 1 ms)
Set dtbo_entry_idx to 0: dtbo_entry_idx 1 >= num_of_dtbo 1.
dtbo_size=52589
after overlay, fdt size(241764)
[PROFILE] ::: fdt = platform_load_device_tree() takes 13 ms
```
- **Base DTB size**: 189,175 bytes
- **DTBO Entry 0 size**: 52,589 bytes (SHA-256: `91d75534e73c219d1701c9a26805487bf0a79ca1ac0ba20015641eb131ca6fc7`)
- **Merged FDT size**: 241,764 bytes

### Stage 4: FDT-Driven Peripheral Drivers
Immediately following overlay application, LK passes the active FDT pointer to hardware initialization routines:
- `mt_gpio_set_default(fdt)` (1 ms)
- `i2c_hw_init(fdt)` (1 ms)
- `disp_init(fdt)` (363 ms): detects panel (`icnl9922c_fhdp_dsi_vdo_boe678_120hz`), allocates scanout framebuffer (`0xFE007000`), configures simplefb
- `leds_init(fdt)` (2 ms)

### Stage 5: LK Dynamic Mutation Chain (`set_fdt` Hooks)
Before handoff, LK executes a chain of registered hook functions to inject runtime hardware states:
```text
videolfb - lcmname    = icnl9922c_fhdp_dsi_vdo_boe678_120hz
set_fdt:34: runs disp_lcm_fill_lcm_dts_phandle hook function
set_fdt:34: runs update_mmc_dts hook function
update_mmc_dts:disable mmc0 when ufs boot
set_fdt:34: runs set_fdt_avb_cmdline hook function
set_fdt:34: runs platform_fdt_set_chipid hook function
set_fdt:34: runs platform_atag_devinfo_data hook function
```
- **`update_mmc_dts`**: On UFS hardware, disables `/soc/mmc@11230000` to prevent unnecessary eMMC probing.
- **`set_fdt_avb_cmdline`**: Injects Android Verified Boot parameters (`androidboot.vbmeta.device`, `androidboot.verifiedbootstate=orange`).

### Stage 6: MBLOCK Physical Memory Node Injection
LK enumerates all allocated physical memory blocks and appends them as explicit nodes under `/reserved-memory` in the FDT:
```text
mblock-reserved-memory is appended successfully
boot_linux_fdt:543: booting linux @ 0x40000000, ramdisk @ 0x66f00000 (52727689) dtb @ 0x47c80000 (253152)
lk finished --> jump to linux kernel 64Bit
```
- Appending the 31 `mblock` nodes increases the FDT size from **241,764 bytes** to **253,152 bytes**.
- This matches byte-for-byte with `/sys/firmware/fdt` dumped from the live running Linux kernel.

---

## 4. Complete Physical Memory Allocation Map (31 Regions)

The following 31 physical memory blocks are dynamically generated and injected into the FDT `/reserved-memory` node during boot:

| ID | Region Name | Physical Base | Size (Hex / Dec) | Mapping Domain / Description |
|---|---|---|---|---|
| R[0] | `dramc-rk0` | `0x13FFFF000` | `0x00001000` (4 KiB) | DRAM Controller Rank 0 Calibration |
| R[1] | `dramc-rk1` | `0x23FFFF000` | `0x00001000` (4 KiB) | DRAM Controller Rank 1 Calibration |
| R[2] | `emi_mbist_buf` | `0x07FFFF000` | `0x00001000` (4 KiB) | Memory BIST Test Buffer |
| R[3] | `RKP_NS` | `0x0D0200000` | `0x00200000` (2 MiB) | Real-time Kernel Protection (Non-Secure) |
| R[4] | `RKP` | `0x0D0000000` | `0x00200000` (2 MiB) | Real-time Kernel Protection (Secure) |
| R[5] | `atf-log-reserved` | `0x0BFE00000` | `0x00200000` (2 MiB) | ARM Trusted Firmware Log Buffer |
| R[6] | `system_bl2-ext` | `0x062F00000` | `0x02000000` (32 MiB) | Bootloader Extension (BL2_EXT) Staging |
| R[7] | `aee_debug_kinfo` | `0x048080000` | `0x00010000` (64 KiB) | Kernel Crash Debug Info |
| R[8] | `pstore` | `0x048090000` | `0x000E0000` (896 KiB) | Persistent RAM Console (ramoops) |
| R[9] | `minirdump` | `0x048170000` | `0x00010000` (64 KiB) | Mini RAM Dump Logging |
| R[10] | `pl-drambuf` | `0x048500000` | `0x00100000` (1 MiB) | Preloader DRAM Scratchpad |
| R[11] | `pl-boottag` | `0x048600000` | `0x00100000` (1 MiB) | Preloader Boot Tag Arguments |
| R[12] | `aee_lk` | `0x050700000` | `0x00800000` (8 MiB) | Little Kernel Exception Buffer |
| R[13] | `scp-A-reserve-share` | `0x0BFF00000` | `0x00020000` (128 KiB) | System Companion Processor (SCP) Shared |
| R[14] | `sspm-reserve-share` | `0x09FE70000` | `0x00010000` (64 KiB) | Secure Sys Power Manager (SSPM) Shared |
| R[15] | `spm-reserve-share` | `0x0BFF20000` | `0x00010000` (64 KiB) | System Power Manager Shared |
| R[16] | `mcupm-reserve-share` | `0x0BFF30000` | `0x00010000` (64 KiB) | Multi-Core μP Manager Shared |
| R[17] | `tee-reserved` | `0x070000000` | `0x06C00000` (108 MiB) | Trustonic Kinibi TEE-OS Core |
| R[18] | `tee-secmem` | `0x07F600000` | `0x00800000` (8 MiB) | TEE Secure Memory Pool |
| R[19] | `tee-tui` | `0x07E600000` | `0x01000000` (16 MiB) | Trusted User Interface Framebuffer |
| R[20] | `BL31-reserved` | `0x048200000` | `0x00200000` (2 MiB) | ARM Trusted Firmware (TF-A BL31) Core |
| R[21] | `framebuffer` | `0x0FE007000` | `0x01FF9000` (~32 MiB) | Hardware Scanout Buffer (`nt36672e` DSI) |
| R[22] | `mb_kernel` | `0x040000000` | `0x07C80000` (124.5 MiB)| Linux Kernel Decompressed Image Staging |
| R[23] | `SCP-reserved` | `0x0BF800000` | `0x00600000` (6 MiB) | System Companion Processor Firmware |
| R[24] | `SSPM-reserved` | `0x09FE80000` | `0x00180000` (1.5 MiB) | Secure System Power Manager Firmware |
| R[25] | `SPM-reserved` | `0x0BF700000` | `0x00100000` (1 MiB) | System Power Manager Firmware |
| R[26] | `MCUPM-reserved` | `0x0BF600000` | `0x00100000` (1 MiB) | Multi-Core μP Manager Firmware |
| R[27] | `scp_A_dma_reserve` | `0x0BFEE0000` | `0x00020000` (128 KiB) | SCP Direct Memory Access Buffer |
| R[28] | `sspm_ap-shared` | `0x09FD60000` | `0x00110000` (1.06 MiB)| SSPM Application Processor Shared DMA |
| R[29] | `consys_emi_reserved` | `0x07F000000` | `0x00500000` (5 MiB) | Connectivity System (Wi-Fi/BT) EMI |
| R[30] | `shared-dma-pool_wifi` | `0x0BF000000` | `0x00600000` (6 MiB) | Wi-Fi Driver Shared DMA Memory Pool |

---

## 5. Verification Tooling

The Device Tree Pipeline is asserted continuously via the `loki` verification suite:

```bash
./loki verify
```

The verification suite automatically performs the following binary checks:
1. **Base DTB Check**: Asserts `lk.img` subpartition `lk_main_dtb` SHA-256 matches `stock_base_dtb_sha256`.
2. **DTBO Check**: Extracts Entry 0 from `dtbo.img` and asserts SHA-256 matches `stock_dtbo_sha256`.
3. **Vendor Boot Identity Check**: Parses the nested Android `DT_TABLE_MAGIC` inside `vendor_boot.img` and verifies **100% binary identity** with `lk_main_dtb`.
