# Safe Hook Entry Points & Execution Proof Methodology

**Target:** MediaTek MT6789 (Helio G99 / MT8781) | ADVAN X1 Firmware Baseline v5  
**Context:** Non-Secure EL1 (Little Kernel) and Secure EL3 (BL2_EXT)

This document maps all verified, safe execution hook sites in the MediaTek stock bootchain and describes how to prove execution reachability via **onscreen visual markers**, **`expdb` forensic registers**, or **serial log output** without breaking the stock bootflow.

---

## 1. Summary of Safe Hook Sites

| Site ID | Subpartition | Location / Mechanism | Phase / Pre-conditions | Primary Proof Channel | Impact on Stock Boot |
|---|---|---|---|---|---|
| **HOOK_APP_FASTBOOT** | `lk` | `0xFFFF000050F99A80` (Descriptor pointer) | Entered on Fastboot triggers (VolUp menu / reboot bootloader) | Onscreen / `expdb` | Zero (chains to stock entry) |
| **HOOK_APP_MTBOOT** | `lk` | `0xFFFF000050F99A98` (Descriptor pointer) | Entered on every normal/recovery boot | Onscreen / `expdb` / UART | Zero (chains to stock entry) |
| **HOOK_TARGET_INIT** | `lk` | `0xFFFF000050F04A2C` (`bl` call site) | Inside `bootstrap2()` after display & PMIC are online | Onscreen / `expdb` | Zero (`target_init` is a stub) |
| **HOOK_KERNEL_DECOMP**| `lk` | `0xFFFF000050F0BD58` (`bl` call site) | Inside `mt_boot()` before kernel LZ4 decompression | `expdb` / memory marker | Zero (calls decompressor) |
| **HOOK_BL2_EXT_SPSR** | `bl2_ext` | `0xFFFF000062F04FBC` (EL3 routine) | Early Secure EL3 before ATF BL31 / LK | `expdb` / SRAM marker | Zero (proceeds to ATF) |

---

## 2. Detailed Breakdown of Each Hook Site

### Hook Site 1: Fastboot App Descriptor Pointer (`HOOK_APP_FASTBOOT`)
* **Address in Memory:** `0xFFFF000050F99A80`
* **File Offset in `00_lk.bin`:** `0x099A80`
* **Mechanism:** Data Pointer Patch. `0x50F99A70` holds the static `struct app_descriptor` for `"fastboot"`:
  ```text
  0x50F99A70: name_ptr  = 0xFFFF000050F76748 ("fastboot")
  0x50F99A78: init_ptr  = 0x0000000000000000
  0x50F99A80: entry_ptr = 0xFFFF000050F05724 (ADDR_LK_APP_FASTBOOT_STOCK_ENTRY)
  ```
* **Why it's safe:**
  - **Zero code modification in `.text`:** Modifies only an 8-byte pointer in the application table.
  - The CPU is in Non-Secure EL1 with MMU and D-Cache enabled.
  - The display, USB MTU3 controller, and watchdog are already fully initialized.
* **Pass-Through Continuation:**
  - At the end of your hook, branch directly to `0xFFFF000050F05724`. Stock USB fastboot continues normally.

---

### Hook Site 2: Android Boot App Descriptor Pointer (`HOOK_APP_MTBOOT`)
* **Address in Memory:** `0xFFFF000050F99AA8`
* **File Offset in `00_lk.bin`:** `0x099AA8`
* **Mechanism:** Data Pointer Patch. `0x50F99A90` holds the static `struct app_descriptor` for `"mt_boot"`:
  ```text
  0x50F99A90: name_ptr  = 0xFFFF000050F78C33 ("mt_boot")
  0x50F99A98: init_ptr  = 0xFFFF000050F0C768
  0x50F99AA0: entry_ptr = 0xFFFF000050F0C87C
  ```
* **Why it's safe:**
  - Triggers on **every boot** (Normal Android boot, Recovery boot, KPOC charger mode).
  - Modifies only the application entry pointer.
* **Pass-Through Continuation:**
  - Branch to stock `0xFFFF000050F0C87C`. Android boots completely unimpeded.

---

### Hook Site 3: `target_init()` Call Site in `bootstrap2()` (`HOOK_TARGET_INIT`)
* **Address in Memory:** `0xFFFF000050F04A2C`
* **File Offset in `00_lk.bin`:** `0x004A2C`
* **Original Opcode:** `bl #0xffff000050f46378`
* **Context:**
  ```arm64
  0xFFFF000050F04A18: bl platform_init       ; Display & PMIC online!
  0xFFFF000050F04A28: bl milestone_logger
  0xFFFF000050F04A2C: bl target_init         ; <-- HOOK SITE
  0xFFFF000050F04A40: bl apps_init           ; Launches fastboot & mt_boot
  ```
* **Why it's safe:**
  - On the ADVAN X1 retail baseline, `target_init` at `0xFFFF000050F46378` is literally just an empty stub containing a single `ret` instruction!
  - Diverting this `bl` to custom proof code executes immediately after the screen is initialized and before any boot decisions are made.
* **Pass-Through Continuation:**
  - Return via `ret` (or branch to `0xFFFF000050F46378`). `bootstrap2()` proceeds directly into `apps_init()`.

---

## 3. How to Prove Execution Reachability

There are three independent channels to prove that a hook executed successfully:

### Channel A: Onscreen Text Marker (Visual Proof)
Because the video console is initialized during `platform_init()`, your hook can render text directly to the active screen:

```arm64
// 1. Position cursor at row 5, col 2
mov  w0, #5
mov  w1, #2
ldr  x8, =ADDR_LK_VIDEO_SET_CURSOR   // 0xFFFF000050F33B9C
blr  x8

// 2. Print confirmation banner
adr  x0, msg_hook_ok
ldr  x8, =ADDR_LK_VIDEO_PRINTF       // 0xFFFF000050F33AD8
blr  x8

// 3. Flush dirty rectangle to panel
mov  w0, wzr                         // left = 0
mov  w1, wzr                         // top = 0
mov  w2, #1080                       // right = 1080
mov  w3, #300                        // bottom = 300
ldr  x8, =ADDR_LK_MT_DISP_UPDATE     // 0xFFFF000050F40B88
blr  x8

msg_hook_ok:
    .asciz "[LOKI] HOOK EXECUTION VERIFIED: 0xCAFEB007\n"
```

### Channel B: Hardware Forensic Register (`expdb` Proof)
The MediaTek MT6789 RGU / Watchdog controller contains non-reset registers that are **preserved across warm reboots** and dumped automatically into the `expdb` flash partition:

* Register: `MT6789_WDT_NONRST_REG` (`0x10007020`)
* Virtual Address in LK: `0xFFFF000010007020`

```arm64
// Write milestone marker 0xCAFEB007 to NONRST register
mov  x8, #0x7020
movk x8, #0x1000, lsl #16
movk x8, #0xffff, lsl #48            // x8 = 0xFFFF000010007020
mov  w9, #0xB007
movk w9, #0xCAFE, lsl #16            // w9 = 0xCAFEB007
str  w9, [x8]
```

**Verification from Android:**
After booting into Android, verify the marker via:
```bash
adb shell su -c 'strings /dev/block/by-name/expdb | grep CAFEB007'
```

### Channel C: UART Serial Console
If UART0 (`0x11002000`) is connected at 921600 baud, `video_printf` and LK print routines output directly to the serial console line.
