# Hardware- & Build-Specific Dead Code Caves in MediaTek Little Kernel

**Target:** MediaTek MT6789 (Helio G99 / MT8781) | ADVAN X1 Baseline v5  
**Execution Domain:** Non-Secure EL1 (`lk`) | `.text` Executable Segment

---

## 1. Why Dead Code Exists in OEM Little Kernel

MediaTek Board Support Packages (BSPs) are architected as unified multi-platform codebases. A single OEM firmware build often compiles in drivers and subsystems for multiple distinct hardware configurations:

1. **Storage Subsystem Multi-Plexing:** MediaTek SoC platforms support both **eMMC** (`msdc`) and **UFS** (`ufs-mtk`). A single Little Kernel binary frequently includes driver trees for both. At boot, a hardware strapping pin or register selects between them. On a device physically wired for UFS (such as the ADVAN X1), the entire eMMC/MSDC driver is permanently unreached at runtime.
2. **Display Panel Variations:** Multiple Liquid Crystal Module (LCM) drivers are compiled in to support second-source display panels. Once the primary panel is identified via DSI read, alternate panel driver functions are never executed.
3. **Factory & Production Testing Harnesses:** Fastboot commands intended strictly for assembly line testing (such as `ultraflash` and `usb2jtag`) remain compiled into retail user builds, gated by debug challenge tokens or hardware test fixtures that are never activated in production.
4. **Empty Vendor Stubs:** OEM board stubs (`target_early_init`, `target_init`) compiled as single-instruction `ret` functions because the vendor omitted platform-specific overrides.

When developers need to run custom payloads (such as in-situ memory dumpers, custom chainloaders, or interactive boot menus) directly inside the `.text` segment without shifting partition boundaries or requiring external flash, **dead-code caves provide large blocks of contiguous, executable (RX) memory**.

---

## 2. Code Placement Strategy Comparison

| Strategy | Contiguous Size | Page Table Permissions | Overwrite Impact | Best Use Case |
|---|---|---|---|---|
| **Linker Zero Regions** (`ZERO_REGION_1`) | **3,272 B** | **Read + Execute (RX)** | Pure zeros (`0x00`); overwrites no existing code | Small hook trampolines (e.g. at `0xFFFF000050F00340`), register markers, visual splash triggers |
| **Dead-Code Caves** (`DEADCODE_MSDC_EMMC`) | **27,456 B** (~**26.8 KiB**) | **Read + Execute (RX)** | Overwrites inert, unreached driver code | Large multi-stage payloads, full interactive boot menus, custom chainloader payloads |
| **Unallocated Flash** (`UNALLOCATED_FLASH`) | **2,051,162 B** (~**1.956 MiB**) | Flash Storage | Pure zeros (`0x00`) trailing container space | Secondary bootloader images (`loki-loader`), standalone Linux kernels, initramfs blobs |

---

## 3. Catalog of Dead Code Caves on the ADVAN X1 (MT6789 UFS)

| Cave Identifier | File Offset in `00_lk.bin` | Virtual Address Range | Size (Bytes) | Category / Hardware Gating | Safety & Reachability Proof |
|---|---|---|---|---|---|
| **`DEADCODE_MSDC_EMMC`** | `0x01F2A0` .. `0x025DE0` | `0xFFFF000050F1F2A0` .. `0xFFFF000050F25DE0` | **27,456 B** (`0x6B40`, 26.8 KiB) | Storage interface strapping | ADVAN X1 uses UFS 2.2; strapping bit 10 is `0`. The single caller (`emmc_init()`) is never reached. |
| **`DEADCODE_MMC_DTS_PATCH`** | `0x0422F0` .. `0x0423F0` | `0xFFFF000050F422F0` .. `0xFFFF000050F423F0` | **256 B** (`0x100`) | Storage FDT update | Patch routine for `/soc/mmc@11230000`; inert on UFS device trees. |
| **`DEADCODE_OEM_ULTRAFLASH`**| `0x007448` .. `0x007500` | `0xFFFF000050F07448` .. `0xFFFF000050F07500` | **184 B** (`0xB8`) | Factory production testing | Fastboot handler for factory jig automated flashing. |
| **`DEADCODE_USB2JTAG`** | `0x0060DC` .. `0x0061B4` | `0xFFFF000050F060DC` .. `0xFFFF000050F061B4` | **216 B** (`0xD8`) | Engineering JTAG switch | Requires debug challenge-response token never present in retail builds. |
| **`STUB_TARGET_EARLY_INIT`** | `0x046374` .. `0x046378` | `0xFFFF000050F46374` .. `0xFFFF000050F46378` | **4 B** | Vendor stub | Empty `ret` instruction. |
| **`STUB_TARGET_INIT`** | `0x046378` .. `0x04637C` | `0xFFFF000050F46378` .. `0xFFFF000050F4637C` | **4 B** | Vendor stub | Empty `ret` instruction. |

---

## 4. Deep-Dive: The 26.8 KiB MSDC/eMMC Driver Cave

### A. The Hardware Strapping Selector
In `platform_init` (offset `0x002528`, VA `0xFFFF000050F02528`), the stock Little Kernel reads hardware strapping registers into `w20` to determine the active storage controller:

```assembly
0xFFFF000050F02528: tbnz     w20, #0xa, #0xffff000050f0253c   ; If bit 10 == 1 -> branch to eMMC path
0xFFFF000050F0252C: bl       #0xffff000050f31784              ; Fall-through: bl ufs_init()
0xFFFF000050F02530: adrp     x20, #0xffff000050f75000         ; "[PROFILE] ::: ufs_init() takes %d ms"
0xFFFF000050F02534: add      x20, x20, #0x67
0xFFFF000050F02538: b        #0xffff000050f02548              ; Continue bootflow
0xFFFF000050F0253C: bl       #0xffff000050f239bc              ; Branch target: bl emmc_init()
0xFFFF000050F02540: adrp     x20, #0xffff000050f75000         ; "[PROFILE] ::: emmc_init() takes %d ms"
0xFFFF000050F02544: add      x20, x20, #0x72
0xFFFF000050F02548: bl       #0xffff000050f0d19c              ; Log profiling timestamp
```

### B. Hardware Physical Wiring
* **Target Board:** ADVAN X1 (Retail Firmware Baseline v5).
* **Storage Type:** **UFS 2.2** (`ufs-mtk` HCI base `0x11270000`).
* **Strapping State:** Bit 10 of `w20` is **permanently zero (`0`)**.
* **Execution Path:** The CPU **always** falls through to `ufs_init` (`0x50F31784`). The instruction at `0x50F0253C` (`bl emmc_init`) is **never executed**.

### C. Isolation Verification
Running `tools/capstone/scan_deadcode.py` confirms:
1. **Total cross-references inside `0x01F2A0` .. `0x025DE0`:** 431 calls, all 100% self-contained within the MSDC driver subtree.
2. **Total incoming callers from the rest of LK:** Exactly **1** (`0x50F0253C` -> `0x50F239BC`), which is the strapping branch proven above to be bypassed.
3. **Cave End Boundary:** The MSDC driver ends cleanly at `0x025DDF` (`ret` at `0x025DDC`). The next instruction at `0x025DE0` is the start of the active PMIC subsystem (`[PMIC]invalid channel number %d`).

**Conclusion:** All **27,456 bytes** between `0xFFFF000050F1F2A0` and `0xFFFF000050F25DE0` are completely dead code on the ADVAN X1 and can be safely repurposed for custom payloads.

---

## 5. Utilizing Dead Code Caves for Custom Payloads

### Step 1: Compile Payload Position-Independent or Linked to Cave VA
Ensure your payload is freestanding ARM64 code linked to the cave address:
```bash
aarch64-linux-gnu-gcc -nostdlib -nostartfiles -fPIE -Ttext=0xFFFF000050F1F2A0 \
    -o payload.elf payload.c
aarch64-linux-gnu-objcopy -O binary payload.elf payload.bin
```
Verify `payload.bin` does not exceed `DEADCODE_MSDC_EMMC_SIZE` (27,456 bytes).

### Step 2: Inject Payload into Cave
Overwrite the dead code range in `00_lk.bin` starting at file offset `0x01F2A0`:
```python
with open("00_lk.bin", "r+b") as f:
    f.seek(0x01F2A0)
    f.write(payload_bytes)
```

### Step 3: Branch into the Cave from a Safe Hook Site
Use a single 32-bit `bl` instruction at any safe hook site (such as `HOOK_SITE_TARGET_INIT_CALL` at `0x50F04A2C` or `HOOK_APP_FASTBOOT` pointer at `0x50F99A80`) to jump into `0xFFFF000050F1F2A0`. Because both sites are in `.text`, the target is well within the +/- 128 MB direct branch limit of ARM64.

---

## 6. Automated Scanner Tool

Run the automated dead-code scanner on any raw Little Kernel binary or composite `lk.img`:
```bash
# Scan default firmware
python3 tools/capstone/scan_deadcode.py

# Or pass custom extracted binary
python3 tools/capstone/scan_deadcode.py path/to/00_lk.bin 0xFFFF000050F00000
```
