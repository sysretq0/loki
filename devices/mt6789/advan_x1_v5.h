/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * advan_x1_v5.h — Golden Reference Stock Symbol & Hardware Register Map
 * Target: ADVAN X1 (Retail Firmware Baseline v5)
 * SoC: MediaTek MT6789 (Helio G99 / MT8781) | Arch: AArch64
 * Stock Container SHA256: a11516b640cfdadfc616dcca9db0160ad72dd473a035830b08ed5802883ae834
 *
 * All function addresses byte-verified against extracted raw binary partitions.
 */

#ifndef ADVAN_X1_V5_H
#define ADVAN_X1_V5_H

#include <stdint.h>

/* --- Subpartition Offsets & Extents inside Composite lk.img --- */
#define MKIMG_HDR_SIZE               512ULL

#define SUBPART_LK_OFFSET            0x000000ULL  /* mkimg header container offset */
#define SUBPART_LK_PAYLOAD_OFFSET    0x000200ULL  /* raw payload container offset (header + 512) */
#define SUBPART_LK_SIZE              0x0A2F20ULL  /* 667,424 bytes (raw execution payload) */
#define SUBPART_LK_CONTAINER_SPAN    0x0A3FB0ULL  /* 671,664 bytes (total container span including certs) */
#define SUBPART_LK_LOAD_VIRT         0xFFFF000050F00000ULL

#define SUBPART_BL2_EXT_OFFSET       0x0A3FB0ULL  /* mkimg header container offset */
#define SUBPART_BL2_EXT_PAYLOAD_OFFSET 0x0A41B0ULL /* raw payload container offset */
#define SUBPART_BL2_EXT_SIZE         0x080E20ULL  /* 527,904 bytes (raw execution payload) */
#define SUBPART_BL2_EXT_CONTAINER_SPAN 0x081ED0ULL /* 532,176 bytes (total span including certs) */
#define SUBPART_BL2_EXT_LOAD_VIRT    0xFFFF000062F00000ULL

#define SUBPART_AEE_OFFSET           0x125E80ULL  /* mkimg header container offset */
#define SUBPART_AEE_PAYLOAD_OFFSET   0x126080ULL  /* raw payload container offset */
#define SUBPART_AEE_SIZE             0x0B50E8ULL  /* 741,608 bytes (raw execution payload) */
#define SUBPART_AEE_CONTAINER_SPAN   0x0B61A0ULL  /* 745,888 bytes (total span including certs) */
#define SUBPART_AEE_LOAD_VIRT        0xFFFF000063F00000ULL

#define SUBPART_DTB_OFFSET           0x1DC020ULL  /* mkimg header container offset */
#define SUBPART_DTB_PAYLOAD_OFFSET   0x1DC220ULL  /* raw payload container offset */
#define SUBPART_DTB_SIZE             0x02E2F7ULL  /* 189,175 bytes (raw DTB payload) */
#define SUBPART_DTB_CONTAINER_SPAN   0x02F386ULL  /* total span including certs up to free space */

/* --- Stock Little Kernel (LK / BL33) Verified Functions --- */
#define ADDR_LK__START               0xFFFF000050F00000ULL
#define ADDR_LK_ENTRY                ADDR_LK__START
#define ADDR_LK_KMAIN                0xFFFF000050F048D8ULL
#define ADDR_LK_THREAD_INIT_EARLY    0xFFFF000050F0EB7CULL
#define ADDR_LK_ARCH_EARLY_INIT      0xFFFF000050F038A0ULL
#define ADDR_LK_PLATFORM_EARLY_INIT  0xFFFF000050F0275CULL
#define ADDR_LK_TARGET_EARLY_INIT    0xFFFF000050F46374ULL
#define ADDR_LK_HEAP_INIT            0xFFFF000050F56EACULL
#define ADDR_LK_BOOTSTRAP2           0xFFFF000050F049E4ULL
#define ADDR_LK_TARGET_INIT          0xFFFF000050F46378ULL
#define ADDR_LK_APPS_INIT            0xFFFF000050F04A64ULL

/* Video Subsystem & Console */
#define ADDR_LK_VIDEO_PRINTF         0xFFFF000050F33AD8ULL
#define ADDR_LK_VIDEO_CLEAN_SCREEN   0xFFFF000050F33BE4ULL
#define ADDR_LK_VIDEO_SET_CURSOR     0xFFFF000050F33B9CULL
#define ADDR_LK_MT_DISP_UPDATE       0xFFFF000050F40B88ULL

/* Keypad & Input */
#define ADDR_LK_DETECT_KEY           0xFFFF000050F5B940ULL
#define KEY_VOL_DOWN                 1
#define KEY_VOL_UP                   6
#define KEY_POWER                    8

/* Block I/O & Storage (UFS) */
#define ADDR_LK_BIO_OPEN_BY_LABEL    0xFFFF000050F55D7CULL
#define ADDR_LK_BIO_CLOSE            0xFFFF000050F55D0CULL
#define ADDR_LK_BIO_READ             0xFFFF000050F55E08ULL
#define ADDR_LK_BIO_WRITE            0xFFFF000050F55E78ULL

/* Fastboot Engine */
#define ADDR_LK_FASTBOOT_REGISTER    0xFFFF000050F04C5CULL
#define ADDR_LK_FASTBOOT_PUBLISH     0xFFFF000050F04D20ULL
#define ADDR_LK_FASTBOOT_OKAY        0xFFFF000050F05008ULL
#define ADDR_LK_FASTBOOT_FAIL        0xFFFF000050F04FE0ULL
#define ADDR_LK_FASTBOOT_INFO        0xFFFF000050F04F50ULL
#define ADDR_LK_FASTBOOT_STOP        0xFFFF000050F0503CULL

/* Threading & Watchdog */
#define ADDR_LK_THREAD_CREATE        0xFFFF000050F0E21CULL
#define ADDR_LK_THREAD_RESUME        0xFFFF000050F0E23CULL
#define ADDR_LK_WDT_PET              0xFFFF000050F33F44ULL
#define ADDR_LK_WDT_SET_TIMEOUT      0xFFFF000050F33F5CULL
#define ADDR_LK_PLATFORM_HALT        0xFFFF000050F15AA8ULL

/* Slot Management & Kernel Boot Transition */
#define ADDR_LK_GET_SUFFIX           0xFFFF000050F14690ULL
#define ADDR_LK_SET_ACTIVE           0xFFFF000050F14AD0ULL
#define ADDR_LK_KERNEL_DECOMPRESS    0xFFFF000050F0A994ULL
#define ADDR_LK_CMDLINE_APPEND       0xFFFF000050F0F800ULL
#define ADDR_LK_FDT_SETPROP          0xFFFF000050F498E8ULL
#define ADDR_LK_ARCH_DISABLE_CACHE   0xFFFF000050F1428CULL
#define ADDR_LK_ARCH_CLEAN_CACHE_DISABLE_MMU_AND_JUMP 0xFFFF000050F140E8ULL
#define ADDR_LK_ARCH_DISABLE_MMU_JMP ADDR_LK_ARCH_CLEAN_CACHE_DISABLE_MMU_AND_JUMP
#define ADDR_LK_BOOT_LINUX           0xFFFF000050F14330ULL
#define ADDR_LK_SMC_BOOT_LINUX_TRAMPOLINE 0xFFFF000050F0C3CCULL
#define ADDR_LK_SMC_BOOT_TRAMPOLINE  ADDR_LK_SMC_BOOT_LINUX_TRAMPOLINE

/* Memory Allocation */
#define ADDR_LK_MALLOC               0xFFFF000050F56FB4ULL
#define ADDR_LK_FREE                 0xFFFF000050F570E4ULL

/* --- Stock Bootloader Extension (BL2_EXT / EL3) Verified Functions --- */
#define ADDR_BL2_EXT__START          0xFFFF000062F00000ULL
#define ADDR_BL2_EXT_ENTRY           ADDR_BL2_EXT__START
#define ADDR_BL2_EXT_BOOTSTRAP2      0xFFFF000062F049E4ULL
#define ADDR_BL2_EXT_SPSR_DROP_ROUTINE 0xFFFF000062F04FBCULL
#define ADDR_BL2_EXT_SPSR_ROUTINE    ADDR_BL2_EXT_SPSR_DROP_ROUTINE
#define ADDR_BL2_EXT_ATF_HANDOFF_JUMP 0xFFFF000062F0C108ULL
#define ADDR_BL2_EXT_ATF_JUMP        ADDR_BL2_EXT_ATF_HANDOFF_JUMP

/* --- Stock Exception Engine (AEE / kedump) --- */
#define ADDR_AEE_KEDUMP_INIT         0xFFFF000063F01000ULL

/* --- SoC Hardware Peripherals (MT6789) --- */
#define MT6789_WDT_BASE              0x10007000ULL
#define MT6789_WDT_MODE              0x10007000ULL
#define MT6789_WDT_LENGTH            0x10007004ULL
#define MT6789_WDT_RESTART           0x10007008ULL
#define MT6789_WDT_NONRST_REG        0x10007020ULL
#define MT6789_WDT_NONRST_REG2       0x10007024ULL

#define MT6789_DEVAPC_BASE           0x1000EF00ULL
#define MT6789_UART0_BASE            0x11002000ULL
#define MT6789_UFSHCI_BASE           0x11270000ULL
#define MT6789_MMSYS_BASE            0x14000000ULL
#define MT6789_DISP_OVL0_BASE        0x14005000ULL

/* Display Scanout Framebuffers */
#define FB_BASE_PHYS_0               0xFE007000ULL
#define FB_BASE_PHYS_1               0xFEA41000ULL
#define FB_WIDTH                     1080
#define FB_HEIGHT                    2400

/* --- Zero-Filled (.text) Executable Padding Regions (No Dead Code Reuse) --- */
/* Region 1: Linker alignment before VBAR_EL1 vector table (3,272 bytes pure 0x00) */
#define ZERO_REGION_1_OFFSET         0x000338ULL
#define ZERO_REGION_1_VIRT           0xFFFF000050F00338ULL
#define ZERO_REGION_1_SIZE           3272ULL
#define PROOF_HOOK_TARGET_VIRT       0xFFFF000050F00340ULL  /* Recommended 16-byte aligned hook entry */

/* Region 2: Linker alignment after VBAR_EL1 vector table (2,948 bytes pure 0x00) */
#define ZERO_REGION_2_OFFSET         0x00187CULL
#define ZERO_REGION_2_VIRT           0xFFFF000050F0187CULL
#define ZERO_REGION_2_SIZE           2948ULL

/* Region 3: Linker alignment at end of .text segment (3,607 bytes pure 0x00) */
#define ZERO_REGION_3_OFFSET         0x0741E9ULL
#define ZERO_REGION_3_VIRT           0xFFFF000050F741E9ULL
#define ZERO_REGION_3_SIZE           3607ULL

/* --- Container Flash Partition Free Space (lk.img) --- */
/* Trailing unallocated partition space (1.956 MiB pure 0x00 flash space) */
#define UNALLOCATED_FLASH_OFFSET     0x20B3A6ULL
#define UNALLOCATED_FLASH_SIZE       0x1F4C5AULL  /* 2,051,162 bytes */
#define CONTAINER_TOTAL_SIZE         0x400000ULL  /* 4,194,304 bytes (4 MiB) */

/* --- Primary Safe Hook Sites --- */
#define HOOK_SITE_TARGET_INIT_CALL   0xFFFF000050F04A2CULL  /* bl call site in bootstrap2 */
#define HOOK_SITE_FASTBOOT_ENTRY_PTR 0xFFFF000050F99A80ULL  /* Fastboot app descriptor entry ptr */
#define HOOK_SITE_MTBOOT_ENTRY_PTR   0xFFFF000050F99AA8ULL  /* mt_boot app descriptor entry ptr */
#define HOOK_SITE_KERNEL_DECOMP_CALL 0xFFFF000050F0BD58ULL  /* bl call site in mt_boot */
#define HOOK_SITE_BL2_EXT_SPSR       0xFFFF000062F04FBCULL  /* EL3 SPSR drop routine in bl2_ext */

/* --- Hardware- & Build-Specific Dead Code Caves (.text) --- */
/* ADVAN X1 uses UFS 2.2 storage; strapping bit 10 is 0. emmc_init() is bypassed. */
/* Entire 27.4 KiB MSDC/eMMC driver is unreached at runtime, safe for in-situ payloads. */
#define DEADCODE_MSDC_EMMC_OFFSET    0x01F2A0ULL
#define DEADCODE_MSDC_EMMC_VIRT      0xFFFF000050F1F2A0ULL
#define DEADCODE_MSDC_EMMC_SIZE      27456ULL     /* 0x6B40 bytes (26.8 KiB) */

/* Unused MMC device tree patch routine */
#define DEADCODE_MMC_DTS_PATCH_OFFSET 0x0422F0ULL
#define DEADCODE_MMC_DTS_PATCH_VIRT  0xFFFF000050F422F0ULL
#define DEADCODE_MMC_DTS_PATCH_SIZE  256ULL

/* Unused factory ultraflash fastboot command */
#define DEADCODE_OEM_ULTRAFLASH_OFFSET 0x007448ULL
#define DEADCODE_OEM_ULTRAFLASH_VIRT 0xFFFF000050F07448ULL
#define DEADCODE_OEM_ULTRAFLASH_SIZE 184ULL

/* Unused engineering USB-to-JTAG switch handler */
#define DEADCODE_USB2JTAG_OFFSET     0x0060DCULL
#define DEADCODE_USB2JTAG_VIRT       0xFFFF000050F060DCULL
#define DEADCODE_USB2JTAG_SIZE       216ULL

#endif /* ADVAN_X1_V5_H */
