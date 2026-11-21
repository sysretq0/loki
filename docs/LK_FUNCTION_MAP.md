# Little Kernel (LK / BL33) Function & Address Map

**Target:** ADVAN X1 Retail Firmware Baseline v5  
**SoC:** MediaTek MT6789 (Helio G99 / MT8781) | ARMv8.2-A (AArch64)  
**Binary Offset:** `0x000000` inside `lk.img` (Length: 667,424 bytes)  
**Execution Context:** Non-Secure EL1 with MMU Enabled (Virtual Base: `0xFFFF000050F00000`)

*Every address listed below has been disassembled and byte-verified against extracted raw binary partitions.*

---

## 1. System Initialization & Kernel Core

### `_start`
* **Address:** `0xFFFF000050F00000` (Offset: `0x000000`)
* **First Instruction:** `bl #0xffff000050f140c0`
* **Description:** Primary entry point for BL33. Verifies execution level is EL1, initializes boot stack pointer, zeros page tables, programs MAIR, TCR, TTBR0, TTBR1, enables `SCTLR_EL1.M`, and jumps to higher-half kernel virtual address.

### `kmain`
* **Address:** `0xFFFF000050F048D8` (Offset: `0x0048D8`)
* **First Instruction:** `stp x29, x30, [sp, #-0x30]!`
* **Description:** Primary C initialization sequence. Sequentially initializes early subsystems and spawns the `bootstrap2` thread.

### `thread_init_early`
* **Address:** `0xFFFF000050F0EB7C` (Offset: `0x00EB7C`)
* **First Instruction:** `stp x29, x30, [sp, #-0x20]!`
* **Caller:** Called by `kmain` at `0x50F048FC`.
* **Description:** Initializes scheduler runqueues and idle thread context.

### `arch_early_init`
* **Address:** `0xFFFF000050F038A0` (Offset: `0x0038A0`)
* **First Instruction:** `stp x29, x30, [sp, #-0x10]!`
* **Caller:** Called by `kmain` at `0x50F04910`.
* **Description:** Reads `cntfrq_el0` and sets up early ARM generic timer timing baselines.

### `platform_early_init`
* **Address:** `0xFFFF000050F0275C` (Offset: `0x00275C`)
* **First Instruction:** `stp x29, x30, [sp, #-0x20]!`
* **Caller:** Called by `kmain` at `0x50F04924`.
* **Description:** Configures UART0 MMIO registers (`0x11002000`) for 921600 baud 8N1 serial logging.

### `target_early_init`
* **Address:** `0xFFFF000050F46374` (Offset: `0x046374`)
* **First Instruction:** `ret` (stub on retail MT6789)
* **Caller:** Called by `kmain` at `0x50F04938`.
* **Description:** Board hardware strapping detection.

### `heap_init`
* **Address:** `0xFFFF000050F56EAC` (Offset: `0x056EAC`)
* **First Instruction:** `sub sp, sp, #0x20`
* **Caller:** Called by `kmain` at `0x50F0494C`.
* **Description:** Initializes the dlmalloc memory allocator pool in physical DRAM.

### `bootstrap2`
* **Address:** `0xFFFF000050F049E4` (Offset: `0x0049E4`)
* **First Instruction:** `stp x29, x30, [sp, #-0x20]!`
* **Description:** High-level system initialization thread spawned by `kmain`.

### `target_init`
* **Address:** `0xFFFF000050F46378` (Offset: `0x046378`)
* **First Instruction:** `ret`
* **Caller:** Called by `bootstrap2` at `0x50F04A2C`.
* **Description:** Target-specific board hardware initialization.

### `apps_init`
* **Address:** `0xFFFF000050F04A64` (Offset: `0x004A64`)
* **First Instruction:** `stp x29, x30, [sp, #-0x40]!`
* **Caller:** Called by `bootstrap2` at `0x50F04A40`.
* **Description:** Iterates the static LK application table (fastboot and mt_boot).

---

## 2. Video Subsystem & Console Rendering

### `video_printf`
* **Address:** `0xFFFF000050F33AD8` (Offset: `0x033AD8`)
* **First Instruction:** `sub sp, sp, #0x1b0`
* **Signature:** `int video_printf(const char *fmt, ...)`
* **Description:** Formats text and renders bitmap glyphs to the DRAM framebuffer.

### `video_clean_screen`
* **Address:** `0xFFFF000050F33BE4` (Offset: `0x033BE4`)
* **First Instruction:** `stp x29, x30, [sp, #-0x20]!`
* **Signature:** `void video_clean_screen(void)`
* **Description:** Clears active framebuffer memory with black pixels.

### `video_set_cursor`
* **Address:** `0xFFFF000050F33B9C` (Offset: `0x033B9C`)
* **First Instruction:** `tbnz w0, #0x1f, #0xffff000050f33bd4`
* **Signature:** `void video_set_cursor(int row, int col)`
* **Description:** Updates text console cursor coordinates.

### `mt_disp_update`
* **Address:** `0xFFFF000050F40B88` (Offset: `0x040B88`)
* **First Instruction:** `stp x29, x30, [sp, #-0x20]!`
* **Signature:** `void mt_disp_update(int left, int top, int right, int bottom)`
* **Description:** Pushes dirty bounding box from DRAM framebuffer to MIPI DSI panel scanout.

---

## 3. Hardware Keypad & Input

### `detect_key`
* **Address:** `0xFFFF000050F5B940` (Offset: `0x05B940`)
* **First Instruction:** `stp x29, x30, [sp, #-0x10]!`
* **Signature:** `int detect_key(unsigned short keycode)`
* **Keycodes:** `1` = VolDown, `6` = VolUp, `2`/`8` = Power.
* **Description:** Reads state of physical hardware buttons from PMIC GPIOs.

---

## 4. Block I/O & Storage (UFS 2.2)

### `bio_open_by_label`
* **Address:** `0xFFFF000050F55D7C` (Offset: `0x055D7C`)
* **First Instruction:** `stp x29, x30, [sp, #-0x30]!`
* **Signature:** `struct bdev *bio_open(const char *name)`
* **Description:** Resolves GPT partition label to a block device descriptor.

### `bio_close`
* **Address:** `0xFFFF000050F55D0C` (Offset: `0x055D0C`)
* **First Instruction:** `stp x29, x30, [sp, #-0x20]!`
* **Signature:** `void bio_close(struct bdev *dev)`

### `bio_read`
* **Address:** `0xFFFF000050F55E08` (Offset: `0x055E08`)
* **First Instruction:** `tbnz x2, #0x3f, #0xffff000050f55e38`
* **Signature:** `ssize bio_read(struct bdev *dev, void *buf, u64 offset, usize len)`

### `bio_write`
* **Address:** `0xFFFF000050F55E78` (Offset: `0x055E78`)
* **First Instruction:** `tbnz x2, #0x3f, #0xffff000050f55ea8`
* **Signature:** `ssize bio_write(struct bdev *dev, const void *buf, u64 offset, usize len)`

---

## 5. Fastboot Engine (MUSB USB Gadget)

### `fastboot_register`
* **Address:** `0xFFFF000050F04C5C` (Offset: `0x004C5C`)
* **First Instruction:** `stp x29, x30, [sp, #-0x40]!`
* **Signature:** `void fastboot_register(const char *prefix, void (*handle)(const char *arg, void *data, unsigned int sz), unsigned int flags)`

### `fastboot_publish`
* **Address:** `0xFFFF000050F04D20` (Offset: `0x004D20`)
* **First Instruction:** `stp x29, x30, [sp, #-0x20]!`
* **Signature:** `void fastboot_publish(const char *name, const char *value)`

### `fastboot_okay`
* **Address:** `0xFFFF000050F05008` (Offset: `0x005008`)
* **First Instruction:** `adrp x8, #0xffff000050f76000`

### `fastboot_fail`
* **Address:** `0xFFFF000050F04FE0` (Offset: `0x004FE0`)
* **First Instruction:** `adrp x0, #0xffff000050f76000`

### `fastboot_info`
* **Address:** `0xFFFF000050F04F50` (Offset: `0x004F50`)
* **First Instruction:** `mov x20, x0`

### `fastboot_stop`
* **Address:** `0xFFFF000050F0503C` (Offset: `0x00503C`)
* **First Instruction:** `adrp x0, #0xffff000050f76000`

---

## 6. Watchdog & Power Control

### `wdt_pet`
* **Address:** `0xFFFF000050F33F44` (Offset: `0x033F44`)
* **First Instruction:** `mov x8, #0x7008`
* **Description:** Writes `0x1971` (`MTK_WDT_RESTART_KEY`) to `0x10007008`.

### `wdt_set_timeout`
* **Address:** `0xFFFF000050F33F5C` (Offset: `0x033F5C`)
* **First Instruction:** `mov x9, #0x7004`
* **Description:** Writes duration key and timeout value to `0x10007004`.

### `platform_halt`
* **Address:** `0xFFFF000050F15AA8` (Offset: `0x015AA8`)
* **First Instruction:** `stp x29, x30, [sp, #-0x50]!`
* **Description:** Triggers shutdown or reboot.

---

## 7. Slot Management & Linux Kernel Handoff

### `get_suffix`
* **Address:** `0xFFFF000050F14690` (Offset: `0x014690`)
* **First Instruction:** `sub sp, sp, #0x30`
* **Description:** Reads active slot status from `misc` BCAB metadata and returns `"_a"` or `"_b"`.

### `set_active`
* **Address:** `0xFFFF000050F14AD0` (Offset: `0x014AD0`)
* **First Instruction:** `sub sp, sp, #0x50`
* **Description:** Compares suffix to `"_a"` / `"_b"` and writes updated BCB block to `misc`.

### `kernel_decompress`
* **Address:** `0xFFFF000050F0A994` (Offset: `0x00A994`)
* **First Instruction:** `sub sp, sp, #0xc0`
* **Description:** Decompresses LZ4 / Gzip kernel image to physical DRAM `0x40000000`.

### `cmdline_append`
* **Address:** `0xFFFF000050F0F800` (Offset: `0x00F800`)
* **First Instruction:** `stp x29, x30, [sp, #-0x30]!`
* **Description:** Appends arguments to the kernel command line buffer.

### `fdt_setprop`
* **Address:** `0xFFFF000050F498E8` (Offset: `0x0498E8`)
* **First Instruction:** `stp x29, x30, [sp, #-0x30]!`
* **Description:** Sets device tree property in memory.

### `arch_disable_cache`
* **Address:** `0xFFFF000050F1428C` (Offset: `0x01428C`)
* **First Instruction:** `stp x29, x30, [sp, #-0x20]!`
* **Description:** Flushes D-cache and I-cache.

### `arch_clean_cache_disable_mmu_and_jump`
* **Address:** `0xFFFF000050F140E8` (Offset: `0x0140E8`)
* **First Instruction:** `mov x5, x0`
* **Description:** Clears `SCTLR_EL1.M`, turns off MMU, and branches to target physical address.

### `boot_linux`
* **Address:** `0xFFFF000050F14330` (Offset: `0x014330`)
* **First Instruction:** `stp x29, x30, [sp, #-0x50]!`
* **Description:** Sets up arguments, masks DAIF, and branches to the SMC trampoline.

### `smc_boot_linux_trampoline`
* **Address:** `0xFFFF000050F0C3CC` (Offset: `0x00C3CC`)
* **First Instruction:** `mov x4, #1`
* **Description:** Physical SMC FID `0xC2000115` trampoline into ATF BL31.
