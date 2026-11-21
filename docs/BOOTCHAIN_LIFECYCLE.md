# MediaTek MT6789 Stock Bootchain Lifecycle & Partition Architecture

**Target Hardware:** MediaTek MT6789 (Helio G99 / MT8781)  
**Reference Firmware:** ADVAN X1 Retail Firmware Baseline v5  
**Platform Architecture:** ARMv8.2-A (AArch64)

---

## 1. Physical Layout of the Composite `lk.img` Partition

In MediaTek architectures, the `lk` partition (and `lk_b` on A/B slot devices) is a **4 MiB multi-image container**. It does not hold a single binary; it packs multiple discrete sub-images compiled from distinct Little Kernel targets, each prefixed with an MTK `mkimg` header (`magic = 0x58881688`) and ASN.1 DER signature certificates (`cert1`, `cert2`):

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                        COMPOSITE lk.img PARTITION (4 MiB Flash)                                       |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| Container Offset  | Sub-Image Name | Payload Size | Component Type    | Domain / Privilege   | Load Address (VA)  |
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
| 0x000000..0x000200| lk (header)    | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x000200..0x0A3120| lk (payload)   | 667,424 B    | Little Kernel 2   | BL33 / Non-Secure EL1| 0xFFFF000050F00000 |
| 0x0A3120..0x0A39D0| cert1          | 1,709 B      | ASN.1 DER Header  | Signature Descriptor | N/A                |
| 0x0A39D0..0x0A3FB0| cert2          | 982 B        | ASN.1 DER Header  | Certificate Key Data | N/A                |
| 0x0A3FB0..0x0A41B0| bl2_ext (hdr)  | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x0A41B0..0x124FD0| bl2_ext (pay)  | 527,904 B    | Bootloader Ext.   | BL2 / Secure EL3     | 0xFFFF000062F00000 |
| 0x124FD0..0x1258A0| cert1          | 1,733 B      | ASN.1 DER Header  | Signature Descriptor | N/A                |
| 0x1258A0..0x125E80| cert2          | 982 B        | ASN.1 DER Header  | Certificate Key Data | N/A                |
| 0x125E80..0x126080| aee (header)   | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x126080..0x1DB168| aee (payload)  | 741,608 B    | Exception Engine  | Exception Core / EL1 | 0xFFFF000063F00000 |
| 0x1DB168..0x1DBA40| cert1          | 1,733 B      | ASN.1 DER Header  | Signature Descriptor | N/A                |
| 0x1DBA40..0x1DC020| cert2          | 982 B        | ASN.1 DER Header  | Certificate Key Data | N/A                |
| 0x1DC020..0x1DC220| dtb (header)   | 512 B        | MTK mkimg Header  | Container Metadata   | N/A                |
| 0x1DC220..0x20A517| lk_main_dtb    | 189,175 B    | Device Tree Blob  | Flattened Device Tree| Staged in DRAM     |
| 0x20A517..0x20ADD0| cert1          | 1,709 B      | ASN.1 DER Header  | Signature Descriptor | N/A                |
| 0x20ADD0..0x20B3A6| cert2          | 982 B        | ASN.1 DER Header  | Certificate Key Data | N/A                |
| 0x20B3A6..0x400000| [Unallocated]  | 2,051,162 B  | Trailing Free     | Pure 0x00 Space      | Unallocated (1.96M)|
+-------------------+----------------+--------------+-------------------+----------------------+--------------------+
```

---

## 2. Complete Unmodified Boot Execution Sequence

```
                                  +-------------------+
                                  |   BROM (EL3 32)   |
                                  +---------+---------+
                                            │
                                            │ Executes from Mask ROM
                                            │ Verifies & loads Preloader to SRAM (0x00201000)
                                            ▼
                                  +-------------------+
                                  |  Preloader (BL2)  |
                                  |    (SRAM, EL3)    |
                                  +---------+---------+
                                            │
                                            │ 1. Initializes PMIC (MT6358 / MT6366)
                                            │ 2. Calibrates LPDDR4X DRAM (Base: 0x40000000)
                                            │ 3. Reads Sub-Image 1 ('bl2_ext') into DRAM
                                            │ 4. Branches to bl2_ext entry at 0xFFFF000062F00000
                                            ▼
+--------------------------------------------------------------------------------------------------+
| STAGE 1: Bootloader Extension (bl2_ext) — Sub-Image 1 (Offset 0x0A3FB0, Secure EL3)              |
|                                                                                                  |
| • An EL3 Little Kernel build running at virtual address 0xFFFF000062F00000                       |
| • Initializes early fuel gauge / battery charging ICs                                            |
| • Allocates physical DRAM for BL33: "vm-BL33-reserved" -> 0x40000000                            |
| • Copies Sub-Image 0 ('lk') into DRAM at 0x40000000                                              |
| • Allocates physical DRAM for BL31: "vm-BL31-reserved" -> 0x48200000                            |
| • Copies ARM Trusted Firmware ('atf') into DRAM at 0x48200000                                    |
| • Configures DevAPC memory firewalls and security configuration registers                        |
| • Configures SPSR drop values (0x4FE8 / 0x4FFC): defaults to 0x3c5 (EL1h)                        |
| • Calls 0xC108: Cleans caches, disables EL3 MMU, and branches to ATF BL31 at 0x48200000          |
+--------------------------------------------------------------------------------------------------+
                                            │
                                            ▼
                                  +-------------------+
                                  |  ARM Trusted FW   |
                                  |   (BL31 @ EL3)    |
                                  +---------+---------+
                                            │
                                            │ 1. Sets up GIC-v3 interrupt distributor & PSCI runtime
                                            │ 2. Evaluates SPSR context passed by bl2_ext
                                            │ 3. Drops execution to Non-Secure EL1
                                            │ 4. Enters Little Kernel 2 (BL33) at 0xFFFF000050F00000
                                            ▼
+--------------------------------------------------------------------------------------------------+
| STAGE 2: Little Kernel 2 (lk) — Sub-Image 0 (Offset 0x000000, Non-Secure EL1)                    |
|                                                                                                  |
| 1. _start (0xFFFF000050F00000):                                                                  |
|    • Sets stack pointer to 0xFFFF000050FD2000                                                    |
|    • Checks CurrentEL at 0x50F03720 (verifies EL1)                                               |
|    • Zeros page tables, configures MAIR, TCR, TTBR0, TTBR1, enables SCTLR_EL1.M (MMU ON)        |
|    • Jumps to higher-half virtual address 0xFFFF000050F00260                                     |
|    • Clears BSS and branches to kmain() at 0xFFFF000050F048D8                                    |
|                                                                                                  |
| 2. kmain() (0xFFFF000050F048D8):                                                                 |
|    • thread_init_early() (0x50F048FC): Scheduler runqueues & idle thread context                 |
|    • arch_early_init()   (0x50F04910): ARM generic timer cntpct_el0 initialization               |
|    • platform_early_init() (0x50F04924): UART0 (0x11002000 @ 921600 baud) and core APB clocks   |
|    • target_early_init() (0x50F04938): Board hardware strapping detection                        |
|    • heap_init()         (0x50F0494C): dlmalloc heap pool initialization                         |
|    • thread_create()     (0x50F049B8): Spawns "bootstrap2" thread (entry 0x50F049E4, 8KB stack)  |
|    • thread_resume()     (0x50F049C8): Starts bootstrap2                                         |
|    • thread_become_idle(): kmain thread enters idle loop                                         |
|                                                                                                  |
| 3. bootstrap2() Thread (0xFFFF000050F049E4):                                                     |
|    • arch_init()     (0x50F04A00)                                                                |
|    • platform_init() (0x50F04A18):                                                               |
|         - pwrap_init() (PMIC bus active)                                                         |
|         - mt_disp_init() (0x50F31248): DSI display, OVL0, RDMA, Backlight ON, FB @ 0xFE007000    |
|    • target_init()   (0x50F04A2C):                                                               |
|         - ufs_init()   (Probes UFS 2.2 host controller, mounts LUNs)                             |
|         - gpt_init()   (Parses GPT headers, block devices online)                                |
|         - keypad_init() (0x50F04B30: detect_key online: VolDown=1, VolUp=6, Power=2)             |
|    • apps_init()     (0x50F04A40):                                                               |
|         - App 0: "fastboot" (0x50F99A70 -> entry 0x50F05724): MUSB USB Fastboot gadget           |
|         - App 1: "mt_boot"  (0x50F99A98 -> init 0x50F0C768, entry 0x50F0C87C): Android Boot    |
|                                                                                                  |
| 4. mt_boot Pipeline (0xFFFF000050F0C87C -> 0xFFFF000050F0C3D8):                                  |
|    • Evaluates reboot reason and hardware keys:                                                  |
|         - VolDown pressed (key 1) -> Factory Mode (boot mode 4)                                  |
|         - VolUp pressed (key 6)   -> activate_menu() (0x50F0A1B8: Recovery/Fastboot/Normal)      |
|         - Reboot reason 2         -> Recovery Mode (boot mode 2)                                 |
|         - Reboot reason 3         -> Fastboot Mode (boot mode 99)                                |
|    • Queries active slot suffix via get_suffix() (0x50F14690)                                    |
|    • Loads boot / recovery partition from UFS into DRAM via bio_read() (0x50F166C8)              |
|    • Decompresses kernel at 0x50F0BD58 (LZ4/Gzip to 0x40000000)                                  |
|    • Injects command line arguments via cmdline_append() (0x50F0F800)                            |
|    • Executes Device Tree Pipeline (see docs/DEVICE_TREE_PIPELINE.md):                           |
|         - Merges lk_main_dtb (189,175 B) with dtbo.img (52,589 B) -> 241,764 B                   |
|         - Runs set_fdt hooks (lcm_phandle, update_mmc_dts, avb_cmdline, chipid)                 |
|         - Injects 31 mblock physical memory reservations into /reserved-memory -> 253,152 B       |
|    • Calls boot_linux_fdt() at 0xFFFF000050F14330:                                               |
|         - Staged addresses: Kernel=0x40000000, Ramdisk=0x66F00000, DTB=0x47C80000                |
|         - Masks DAIF (msr daifset, #0x2)                                                         |
|         - Flushes caches to PoC via arch_disable_cache(3) at 0x50F1428C                          |
|         - Calls arch_clean_cache_disable_mmu_and_jump() at 0x50F140E8:                           |
|             * Clears SCTLR_EL1.M (TURNS OFF MMU)                                                 |
|             * Jumps to physical trampoline at 0x50F0C3CC:                                        |
|                 mov x4, #1                                                                       |
|                 smc #0  (FID 0xC2000115: MTK_SIP_KERNEL_BOOT_AARCH64)                            |
+--------------------------------------------------------------------------------------------------+
                                            │
                                            ▼
                                  +-------------------+
                                  | Linux Kernel EL1  |
                                  | (stext @ 0x40000) |
                                  +-------------------+
```
