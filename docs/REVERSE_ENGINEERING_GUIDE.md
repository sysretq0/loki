# MediaTek LK Reverse-Engineering & Symbol Discovery Guide

This guide details how to locate stock Little Kernel (LK), Bootloader Extension (BL2_EXT), and Exception Engine (AEE) functions from scratch on any MediaTek SoC using **PyGhidra**, **Radare2**, **Rizin**, and **Capstone**.

---

## 1. Unpacking the Partition

Before analyzing, extract the discrete subpartitions from the composite `lk.img`:

```bash
python3 tools/unpack.py path/to/lk.img extracted/
```

This yields:
* `00_lk.bin` (Little Kernel BL33)
* `03_bl2_ext.bin` (Bootloader Extension EL3)
* `06_aee.bin` (Exception Engine EL1)
* `09_lk_main_dtb.bin` (Flattened Device Tree)

---

## 2. Using Capstone (Fast CLI Automated Scanning)

Capstone provides immediate, lightweight pattern scanning with zero external heavy dependencies.

### Scanning Little Kernel (`00_lk.bin`)
```bash
python3 tools/capstone/scan_lk.py extracted/00_lk.bin
```
**What it scans:**
* **SMC Boot Linux Trampoline:** Scans for opcode `smc #0` (with preceding `mov x4, #1`).
* **Watchdog Registers:** Scans for `mov w*, #0x1971` (the MTK watchdog restart key).
* **MMU Disable Pattern:** Scans for `mrs x*, sctlr_el1` followed by `bic x*, x*, #1` and `msr sctlr_el1, x*`.
* **String Anchors:** Finds file offsets for `"fastboot_init"`, `"detect_key"`, `"bootstrap2"`, `"bootargs_ext"`, `"BCAB"`.

### Scanning BL2_EXT (`03_bl2_ext.bin`)
```bash
python3 tools/capstone/scan_bl2_ext.py extracted/03_bl2_ext.bin
```
**What it scans:**
* **SPSR Privilege Drop Sites:** Scans for `mov x*, #0x3c5` followed immediately by `msr spsr_el3` and `msr spsr_el2`.
* **Memory Staging Pools:** Scans for `"vm-BL33-reserved"`, `"vm-BL31-reserved"`, `"atf"`.

---

## 3. Using Radare2 (`r2`) & Rizin (`rz`)

Radare2 and Rizin allow fast, interactive disassembly in the terminal without GUI overhead.

### Step 1: Open the binary with base virtual address
For LK (`00_lk.bin`):
```bash
r2 -a arm -b 64 -B 0xffff000050f00000 extracted/00_lk.bin
# Or with rizin:
rz -a arm -b 64 -m 0xffff000050f00000 extracted/00_lk.bin
```

### Step 2: Search for key string anchors
```r2
# Search for video printf anchor
/ video_printf

# Search for fastboot commands
/ fastboot_init

# Search for keypad detection
/ detect_key

# Search for slot suffix magic
/ BCAB
```

### Step 3: Trace Cross-References (`axt`)
When a string is found at address `0x...`:
```r2
# Analyze function containing the string
af @ <address>

# Find references to this address
axt @ <address>

# Disassemble the referencing function
pdf @ <caller_address>
```

### Step 4: Loading the Golden Reference Script
```bash
r2 -i tools/radare2/lk_map.r2 -B 0xffff000050f00000 extracted/00_lk.bin
```

---

## 4. Using PyGhidra (Automated Headless Decompilation)

PyGhidra allows scriptable decompilation, data type propagation, and automated cross-reference mapping across entire firmware baselines.

### Running Headless Analysis
```bash
GHIDRA_INSTALL_DIR=/opt/ghidra JAVA_TOOL_OPTIONS='-Xmx640m' \
  /opt/ghidra-py/venv/bin/pyghidra --project-path ~/ghidra-projects \
  --project-name lk_analysis extracted/00_lk.bin tools/pyghidra/analyze_lk.py
```

### How to Manually Identify Key Functions in Ghidra

1. **`target_init` & `apps_init`:**
   * Search for string `"bootstrap2"`.
   * Find xref to the function that spawns the thread (`kmain`).
   * Follow `bootstrap2` thread entry: the fourth function call is `target_init()`, and the fifth is `apps_init()`.
2. **`detect_key` (Keypad Polling):**
   * Search for immediate values `1` (`KEY_VOL_DOWN`), `6` (`KEY_VOL_UP`), and `8` (`KEY_POWER`).
   * In LK, key detection compares against these integer constants to route recovery, fastboot, and factory boot modes.
3. **`bio_open` & `bio_read` (UFS Storage):**
   * Search for string `"boot"` or `"recovery"`.
   * The function opening the partition descriptor takes a single string parameter (`bio_open`).
   * The subsequent function performing the read takes 4 arguments (`dev`, `buf`, `offset`, `len`) (`bio_read`).
4. **`video_printf`:**
   * Search for string `"[FASTBOOT]"` or `"video_printf"`.
   * Trace the caller; the function accepting formatting strings and printing to the screen buffer is `video_printf`.
5. **`boot_linux` & `arch_clean_cache_disable_mmu_and_jump`:**
   * Search for instruction `smc #0`.
   * Check register setup before the SMC: `mov x4, #1` indicates the `MTK_SIP_KERNEL_BOOT_AARCH64` protocol.
   * Trace callers backward to locate cache flushing and MMU disablement routines.
