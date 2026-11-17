# Comprehensive Catalog of Safe Hook Entry Points & Zero-Region Placement

**Target:** MediaTek MT6789 (Helio G99 / MT8781) | ADVAN X1 Firmware Baseline v5  
**Scope:** Complete lifecycle of Little Kernel (LK / BL33) and Bootloader Extension (BL2_EXT / EL3)

---

## 1. Zero-Filled Code Regions in Little Kernel (`.text`)

Instead of reusing dead or unreferenced driver code, Little Kernel contains large **linker-inserted alignment padding regions filled with pure `0x00` bytes**. Because these regions reside directly inside the `.text` executable segment, they are mapped **Read + Execute (RX)** by default under stock LK page tables.

| Region ID | File Offset in `00_lk.bin` | Virtual Address Range | Size (Bytes) | Origin / Cause | Executable (RX) |
|---|---|---|---|---|---|
| **ZERO_REGION_1** | `0x000338` .. `0x001000` | `0xFFFF000050F00338` .. `0xFFFF000050F01000` | **3,272 B** (`0xCC8`) | Alignment padding before `VBAR_EL1` vector table | **YES (RX)** |
| **ZERO_REGION_2** | `0x00187C` .. `0x002400` | `0xFFFF000050F0187C` .. `0xFFFF000050F02400` | **2,948 B** (`0xB84`) | Alignment padding after `VBAR_EL1` vector table | **YES (RX)** |
| **ZERO_REGION_3** | `0x0741E9` .. `0x075000` | `0xFFFF000050F741E9` .. `0xFFFF000050F75000` | **3,607 B** (`0xE17`) | Alignment padding at end of `.text` segment | **YES (RX)** |

> **Recommended Safe Placement:** `0xFFFF000050F00340` (inside **ZERO_REGION_1**).  
> It has 3,264 bytes of contiguous zeros, zero collisions with code/data, and is within direct 26-bit branch range (`+/- 128 MB`) from anywhere in the kernel.

---

## 2. Complete Catalog of Safe Hook Sites Across the Bootchain

A hook is classified as **safe** if:
1. It executes in a well-defined hardware state with MMU active.
2. It has a clean pass-through return path that does not disrupt normal bootflow.
3. It does not corrupt register state (`x19-x30`, `sp` preserved).

### Phase 1: Early Kernel Initialization (`kmain` Sequence)

#### 1. Universal Milestone Logger Entry (`HOOK_MILESTONE_ENTRY`)
* **Address:** `0xFFFF000050F047A4` (Offset: `0x0047A4`)
* **Mechanism:** Function replacement / wrapper.
* **Context:** Called at every single LK initialization step (`0x50F0490C`, `0x50F04920`, `0x50F04934`, `0x50F04948`, `0x50F049FC`, `0x50F04A14`, `0x50F04A28`, `0x50F04A3C`, `0x50F04A50`) with `w1 = phase_id`.
* **Milestone IDs:**
  * `w1 = 0x20000`: After `thread_init_early`
  * `w1 = 0x30000`: After `arch_early_init` (Generic Timer online)
  * `w1 = 0x40000`: After `platform_early_init` (UART0 online)
  * `w1 = 0x50000`: After `target_early_init`
  * `w1 = 0x60000`: After `heap_init` (DRAM heap online)
  * `w1 = 0x80000`: After `arch_init`
  * `w1 = 0x90000`: After `platform_init` (MIPI DSI Display & PMIC online)
  * `w1 = 0xA0000`: After `target_init` (UFS Storage online)
  * `w1 = 0xB0000`: After `apps_init`
* **Why it's safe:** Universal lifecycle observer; hook receives phase IDs and calls original `0x50F047A4`.

#### 2. `target_early_init` Call Site (`HOOK_TARGET_EARLY_INIT`)
* **Address:** `0xFFFF000050F04938` (Offset: `0x004938`)
* **Original Opcode:** `bl #0xffff000050f46374` (target function is a `ret` stub).
* **Context:** Called in early `kmain()` before heap initialization.

---

### Phase 2: Secondary System Initialization (`bootstrap2` Sequence)

#### 3. `target_init` Call Site (`HOOK_TARGET_INIT`)
* **Address:** `0xFFFF000050F04A2C` (Offset: `0x004A2C`)
* **Original Opcode:** `bl #0xffff000050f46378` (`0x94010653`)
* **Replacement Opcode for ZERO_REGION_1:** `bl #0xffff000050f00340` (`0x97FFE445`)
* **Context:** Called in `bootstrap2()` right after `platform_init()` (display, backlight, and PMIC are up) and right before `apps_init()`.
* **Why it's safe:** `target_init` on retail MT6789 is an empty `ret` stub. Replacing this branch executes your hook with full display and storage online, then returns cleanly.

---

### Phase 3: Application Descriptors (`apps_init` Sequence)

#### 4. Fastboot Application Entry Pointer (`HOOK_APP_FASTBOOT`)
* **Address:** `0xFFFF000050F99A80` (Offset: `0x099A80`)
* **Original Pointer:** `0xFFFF000050F05724` (`ADDR_LK_APP_FASTBOOT_STOCK_ENTRY`)
* **Mechanism:** 64-bit data pointer in `struct app_descriptor` table.
* **Context:** Triggers only when Fastboot mode is selected.
* **Why it's safe:** Pure data modification; zero `.text` modification. Chains to `0x50F05724`.

#### 5. Android Boot (`mt_boot`) Init Pointer (`HOOK_APP_MTBOOT_INIT`)
* **Address:** `0xFFFF000050F99AA0` (Offset: `0x099AA0`)
* **Original Pointer:** `0xFFFF000050F0C768`
* **Context:** Application initialization callback executed during `apps_init()`.

#### 6. Android Boot (`mt_boot`) Entry Pointer (`HOOK_APP_MTBOOT_ENTRY`)
* **Address:** `0xFFFF000050F99AA8` (Offset: `0x099AA8`)
* **Original Pointer:** `0xFFFF000050F0C87C`
* **Context:** Main boot thread entry point. Triggers on **every boot** (Normal, Recovery, KPOC).
* **Why it's safe:** Data pointer patch; chains to `0x50F0C87C` for uninterrupted Android boot.

#### 7. Application Thread Dispatcher Trampoline (`HOOK_APP_THREAD_DISPATCH`)
* **Address:** `0xFFFF000050F04B68` (Offset: `0x004B68`)
* **Original Opcode:** `blr x8` inside `app_thread_entry`
* **Context:** Universal interceptor for every spawned application thread.

---

### Phase 4: Boot Mode & Decision Engine (`mt_boot` Pipeline)

#### 8. Preloader Reboot Reason Evaluation (`HOOK_REBOOT_REASON`)
* **Address:** `0xFFFF000050F09D14` (Offset: `0x009D14`)
* **Context:** Where LK reads reboot reason registers (Mode 2 = Recovery, Mode 99 = Fastboot).

#### 9. Hardware Key Menu Call Site (`HOOK_ACTIVATE_MENU`)
* **Address:** `0xFFFF000050F0A1B8` (Offset: `0x00A1B8`)
* **Original Target:** `activate_menu()` (Stock MediaTek VolUp selection menu).
* **Context:** Triggers when Volume Up is held at boot.

#### 10. Kernel Power-Off Charging Gate (`HOOK_KPOC_CHECK`)
* **Address:** `0xFFFF000050F09D6C` (Offset: `0x009D6C`)
* **Context:** Evaluates whether USB charger is plugged in without power key pressed.

---

### Phase 5: Kernel Staging & Linux Handoff

#### 11. Kernel Decompress Call Site (`HOOK_KERNEL_DECOMPRESS`)
* **Address:** `0xFFFF000050F0BD58` (Offset: `0x00BD58`)
* **Original Opcode:** `bl #0xffff000050f0a994`
* **Context:** Executes right after `boot.img` is loaded from UFS into DRAM, immediately before decompressing into `0x40000000`.

#### 12. Linux Command Line Append Call Site (`HOOK_CMDLINE_APPEND`)
* **Address:** `0xFFFF000050F0BF6C` (Offset: `0x00BF6C`)
* **Original Opcode:** `bl #0xffff000050f0f800`
* **Context:** Called during boot argument generation; allows parameter inspection or modification.

#### 13. DTB `/chosen` Property Setter Call Site (`HOOK_FDT_SETPROP`)
* **Address:** `0xFFFF000050F0C08C` (Offset: `0x00C08C`)
* **Original Opcode:** `bl #0xffff000050f498e8`
* **Context:** Stages DTB node properties in DRAM before kernel handover.

#### 14. `boot_linux` Entry (`HOOK_BOOT_LINUX`)
* **Address:** `0xFFFF000050F14330` (Offset: `0x014330`)
* **Context:** Final LK function; masks `DAIF`, flushes caches, turns off MMU.

#### 15. Pre-SMC Physical Trampoline (`HOOK_SMC_TRAMPOLINE`)
* **Address:** `0xFFFF000050F0C3CC` (Offset: `0x00C3CC`)
* **Original Opcodes:** `mov x4, #1; smc #0` (FID `0xC2000115`)
* **Context:** Final physical code executed in LK before ATF BL31 jumps to kernel `stext`.

---

### Phase 6: Secure EL3 (`bl2_ext`) Hook Sites

#### 16. `bl2_ext` Memory Staging Call Site (`HOOK_BL2_EXT_STAGING`)
* **Address:** `0xFFFF000062F04EE8` (Offset: `0x004EE8`)
* **Context:** Prepares `"vm-BL33-reserved"` and `"vm-BL31-reserved"` DRAM pools.

#### 17. SPSR Privilege Configuration Routine (`HOOK_BL2_EXT_SPSR`)
* **Address:** `0xFFFF000062F04FBC` (Offset: `0x004FBC`)
* **Context:** Checks `CurrentEL` and writes `0x3c5` to `spsr_el3` (`0x4FE8`) and `spsr_el2` (`0x4FFC`).

---

## 3. The 3 Verification Proof Channels

Each safe hook can prove its execution using three non-disruptive channels:

1. **Onscreen Visual Text Marker:**
   * Uses `video_set_cursor` (`0x50F33B9C`), `video_printf` (`0x50F33AD8`), and `mt_disp_update` (`0x50F40B88`).
   * Renders confirmation text directly to the panel.
2. **Forensic Hardware Register (`expdb` / NONRST):**
   * Writes milestone marker `0xCAFEB007` to `MT6789_WDT_NONRST_REG` (`0xFFFF000010007020`).
   * Survives warm reboots and is verified via `adb shell su -c 'strings /dev/block/by-name/expdb | grep CAFEB007'`.
3. **Serial Console Log Output:**
   * Outputs directly over UART0 (`0x11002000 @ 921600 baud`).
