# Little Kernel (LK / BL33) Function & Address Map

**Target:** ADVAN X1 Retail Firmware Baseline v5  
**SoC:** MediaTek MT6789 (Helio G99 / MT8781) | ARMv8.2-A (AArch64)  
**Binary Offset:** `0x000000` inside `lk.img` (Length: 667,424 bytes)  
**Execution Context:** Non-Secure EL1 with MMU Enabled (Virtual Base: `0xFFFF000050F00000`)

---

## 1. System Initialization & Kernel Core

### `_start`
* **Address:** `0xFFFF000050F00000`
* **Calling Convention:** Hardware Reset / Hand-off from ATF BL31
* **Disassembly Anchor:** `mrs x0, CurrentEL; b.ne drop_el`
* **Description:** Primary entry point for BL33. Verifies execution level is EL1, initializes boot stack pointer (`0xFFFF000050FD2000`), zeros page tables, programs MAIR, TCR, TTBR0, TTBR1, enables `SCTLR_EL1.M`, and jumps to the higher-half virtual kernel mapping at `0xFFFF000050F00260`.

### `kmain`
* **Address:** `0xFFFF000050F048D8`
* **Signature:** `void kmain(void)`
* **Description:** Primary C initialization sequence. Initializes scheduler, generic timer, early UART, heap, spawns the `bootstrap2` thread, and transforms the primary thread into the system idle loop.

### `thread_init_early`
* **Address:** `0xFFFF000050F048FC`
* **Signature:** `void thread_init_early(void)`
* **Description:** Sets up scheduler runqueues and initializes the current thread context structure for the boot thread.

### `arch_early_init`
* **Address:** `0xFFFF000050F04910`
* **Signature:** `void arch_early_init(void)`
* **Description:** Reads `cntfrq_el0` and sets up early ARMv8 generic counter timing baselines.

### `platform_early_init`
* **Address:** `0xFFFF000050F04924`
* **Signature:** `void platform_early_init(void)`
* **Description:** Configures UART0 MMIO registers (`0x11002000`) for 921600 baud 8N1 serial logging and early APB bus clocks.

### `heap_init`
* **Address:** `0xFFFF000050F0494C`
* **Signature:** `void heap_init(void)`
* **Description:** Initializes the dlmalloc memory allocator pool in physical DRAM (`_heap_start` to `_heap_end`).

### `bootstrap2`
* **Address:** `0xFFFF000050F049E4`
* **Signature:** `int bootstrap2(void *arg)`
* **Description:** High-level system initialization thread. Sequentially calls `arch_init()`, `platform_init()` (display, PMIC), `target_init()` (UFS storage, keys), and `apps_init()`.

### `target_init`
* **Address:** `0xFFFF000050F04A2C`
* **Signature:** `void target_init(void)`
* **Description:** Probes the UFS 2.2 host controller, initializes GPT partition tables, registers block I/O devices, and arms keypad polling (`detect_key`).

### `apps_init`
* **Address:** `0xFFFF000050F04A40`
* **Signature:** `void apps_init(void)`
* **Description:** Iterates the static LK application table:
  * Fastboot gadget: App descriptor at `0x50F99A70`, entry pointer at `0x50F99A80` -> `0x50F05724`.
  * Boot engine (`mt_boot`): App descriptor at `0x50F99A98`, entry at `0x50F0C87C`.

---

## 2. Video Subsystem & Console Rendering

### `video_clean_screen`
* **Address:** `0xFFFF000050F089E4`
* **Signature:** `void video_clean_screen(void)`
* **Description:** Clears the active virtual framebuffer buffer with black pixels (`0x00000000`).

### `video_set_cursor`
* **Address:** `0xFFFF000050F08B34`
* **Signature:** `void video_set_cursor(int row, int col)`
* **Parameters:** `row` = vertical character position, `col` = horizontal character position.
* **Description:** Moves text rendering coordinates in the console character grid.

### `video_printf`
* **Address:** `0xFFFF000050F08B9C`
* **Signature:** `int video_printf(const char *fmt, ...)`
* **Description:** Formats text and draws bitmap glyphs into the DRAM framebuffer at the current cursor coordinates.

### `mt_disp_init`
* **Address:** `0xFFFF000050F31248`
* **Signature:** `void mt_disp_init(void *fdt)`
* **Description:** Parses display parameters from `lk_main_dtb`, initializes MIPI DSI transmitter, DISP_OVL0, RDMA, backlight PWM, and assigns framebuffers (`0xFE007000` / `0xFEA41000`).

### `mt_disp_update`
* **Address:** `0xFFFF000050F33A9C`
* **Signature:** `void mt_disp_update(int left, int top, int right, int bottom)`
* **Parameters:** `left`, `top`, `right`, `bottom` bounding rectangle in panel coordinates.
* **Description:** Flushes the dirty rectangular framebuffer region to the MIPI DSI panel scanout.

---

## 3. Hardware Keypad & Input

### `detect_key`
* **Address:** `0xFFFF000050F04B30`
* **Signature:** `int detect_key(unsigned short keycode)`
* **Parameters:**
  * `1` = Volume Down (`KEY_VOL_DOWN`)
  * `6` = Volume Up (`KEY_VOL_UP`)
  * `8` = Power (`KEY_POWER`)
* **Returns:** `1` if key is currently depressed, `0` if released.
* **Description:** Polls PMIC and SoC GPIO key state registers.

---

## 4. Block I/O & Storage (UFS 2.2)

### `bio_open`
* **Address:** `0xFFFF000050F16688`
* **Signature:** `struct bdev *bio_open(const char *name)`
* **Description:** Looks up GPT partition table by ASCII partition name (e.g., `"boot_a"`, `"boot_b"`, `"recovery"`) and returns an allocated block device handle.

### `bio_read`
* **Address:** `0xFFFF000050F166C8`
* **Signature:** `ssize bio_read(struct bdev *dev, void *buf, u64 offset, usize len)`
* **Description:** Issues SCSI read commands over the UFSHCI host controller to read `len` bytes from partition `offset` into memory buffer `buf`.

### `bio_close`
* **Address:** `0xFFFF000050F16730`
* **Signature:** `void bio_close(struct bdev *dev)`
* **Description:** Releases the block device descriptor.

---

## 5. Fastboot Engine (MTU3 USB Gadget)

### `fastboot_register`
* **Address:** `0xFFFF000050F07BD4`
* **Signature:** `void fastboot_register(const char *prefix, void (*handle)(const char *arg, void *data, unsigned int sz), unsigned int flags)`
* **Description:** Registers an ASCII prefix command handler in the fastboot command lookup table.

### `fastboot_publish`
* **Address:** `0xFFFF000050F07C04`
* **Signature:** `void fastboot_publish(const char *name, const char *value)`
* **Description:** Publishes a key/value response string returned by `fastboot getvar <name>`.

### `fastboot_okay`
* **Address:** `0xFFFF000050F07C68`
* **Signature:** `void fastboot_okay(const char *reason)`
* **Description:** Transmits an `"OKAY"` response over the USB endpoint.

### `fastboot_fail`
* **Address:** `0xFFFF000050F07C8C`
* **Signature:** `void fastboot_fail(const char *reason)`
* **Description:** Transmits a `"FAIL"` packet with an error explanation string.

### `fastboot_info`
* **Address:** `0xFFFF000050F07CB0`
* **Signature:** `void fastboot_info(const char *msg)`
* **Description:** Transmits an `"INFO"` text line to the host console during long operations.

### `fastboot_stop`
* **Address:** `0xFFFF000050F07CF4`
* **Signature:** `void fastboot_stop(void)`
* **Description:** Disconnects and quiesces the MTU3 USB gadget.

---

## 6. Watchdog & Power Control

### `wdt_set_timeout`
* **Address:** `0xFFFF000050F04CA8`
* **Signature:** `void wdt_set_timeout(u32 seconds)`
* **Description:** Programs MT6789 RGU / Watchdog timer counter (`0x10007004`).

### `wdt_pet`
* **Address:** `0xFFFF000050F04CD8`
* **Signature:** `void wdt_pet(void)`
* **Description:** Writes `0x1971` (`MTK_WDT_RESTART_KEY`) to `0x10007008` to prevent automatic hardware reset.

### `platform_halt`
* **Address:** `0xFFFF000050F0419C`
* **Signature:** `void platform_halt(int action, int reason)`
* **Parameters:** `action` (0=reboot, 1=shutdown), `reason` (reboot reason flags).
* **Description:** Triggers PMIC power-off or initiates hardware reset via the watchdog.

---

## 7. Slot Management & Linux Kernel Handoff

### `get_suffix`
* **Address:** `0xFFFF000050F14690`
* **Signature:** `const char *get_suffix(void)`
* **Returns:** Pointer to string `"_a"` or `"_b"`.
* **Description:** Reads active slot status from the BCB / `misc` metadata.

### `set_active`
* **Address:** `0xFFFF000050F146C4`
* **Signature:** `int set_active(const char *suffix)`
* **Description:** Updates the active slot suffix in persistent storage.

### `kernel_decompress`
* **Address:** `0xFFFF000050F0BD58`
* **Signature:** `int kernel_decompress(void *src, void *dst, usize src_len, usize dst_len)`
* **Description:** Decompresses LZ4 / Gzip kernel image payload from the boot partition into DRAM at physical `0x40000000`.

### `cmdline_append`
* **Address:** `0xFFFF000050F0F800`
* **Signature:** `int cmdline_append(const char *str)`
* **Description:** Appends a null-terminated argument string to the kernel boot parameters buffer.

### `arch_disable_cache`
* **Address:** `0xFFFF000050F1428C`
* **Signature:** `void arch_disable_cache(u32 flags)`
* **Description:** Cleans and invalidates data caches and instruction caches to the Point of Coherency (PoC).

### `arch_clean_cache_disable_mmu_and_jump`
* **Address:** `0xFFFF000050F140E8`
* **Signature:** `void arch_clean_cache_disable_mmu_and_jump(u64 target_phys, u64 a0, u64 a1, u64 a2, u64 a3)`
* **Description:** Clears `SCTLR_EL1.M`, turns off the MMU, executes an ISB, and branches directly to `target_phys`.

### `boot_linux`
* **Address:** `0xFFFF000050F14330`
* **Signature:** `void boot_linux(void *kernel_addr, void *dtb_addr)`
* **Description:** High-level handoff coordinator. Masks interrupts (`DAIF`), flushes caches, turns off MMU, and jumps to the physical SMC trampoline.

### `smc_boot_linux_trampoline`
* **Address:** `0xFFFF000050F0C3CC`
* **Anchor:** `mov x4, #1; smc #0`
* **Description:** Physical assembly instruction sequence that executes SMC with FID `0xC2000115` (`MTK_SIP_KERNEL_BOOT_AARCH64`), handing execution off to ARM Trusted Firmware BL31 to jump into the Linux kernel `stext` entry point.
