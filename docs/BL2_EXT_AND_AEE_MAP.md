# Bootloader Extension (BL2_EXT) & Exception Engine (AEE) Map

**Target:** ADVAN X1 Retail Firmware Baseline v5  
**SoC:** MediaTek MT6789 (Helio G99 / MT8781) | ARMv8.2-A (AArch64)

---

## 1. Bootloader Extension (`bl2_ext`) — Sub-Image 1

* **Offset inside `lk.img`:** `0x0A3FB0`
* **Size:** 527,904 bytes
* **Domain / Execution Level:** Secure EL3
* **Load Virtual Address:** `0xFFFF000062F00000`

`bl2_ext` is an EL3 Little Kernel build running early in the bootchain. It is staged by Preloader into physical DRAM, executes before ARM Trusted Firmware (BL31), and acts as the secure platform master.

### Mapped Functions & Anchor Sites

#### `_start`
* **Address:** `0xFFFF000062F00000`
* **Privilege:** Secure EL3
* **Description:** Initializes EL3 exception vectors, programs Secure EL3 MMU page tables, and enters `kmain()`.

#### `bootstrap2`
* **Address:** `0xFFFF000062F049E4`
* **Signature:** `int bootstrap2(void *arg)`
* **Description:** Secondary initialization thread for EL3. Initializes PMIC, charger ICs (e.g., `cw221x`, `upm6910`), and prepares physical memory reservations.

#### `bl2_ext_boot_app_desc`
* **Address:** `0xFFFF000062F78558`
* **Description:** Application descriptor for `bl2_ext_boot` payload loader thread. Contains entry pointer `0xFFFF000062F06470`.

#### `app_load_bl33`
* **Address:** `0xFFFF000062F04EE8`
* **Description:** The primary platform staging routine:
  1. Carves out physical DRAM region `"vm-BL33-reserved"` at `0x40000000`.
  2. Copies Sub-Image 0 (`lk`) into physical DRAM at `0x40000000`.
  3. Carves out physical DRAM region `"vm-BL31-reserved"` at `0x48200000`.
  4. Copies ARM Trusted Firmware (`atf`) into physical DRAM at `0x48200000`.
  5. Configures DevAPC memory access permissions.

#### SPSR Drop Sites
* **SPSR_EL3 Site:** `0xFFFF000062F04FE8` (`mov x4, #0x3c5; msr spsr_el3, x4`)
* **SPSR_EL2 Site:** `0xFFFF000062F04FFC` (`mov x4, #0x3c5; msr spsr_el2, x4`)
* **Description:** Configures the Saved Program Status Register (SPSR) context passed to ARM Trusted Firmware. The value `0x3c5` represents `M[3:0] = 0b0101` (EL1h), causing ATF to drop execution to Non-Secure EL1 when entering BL33.

#### `atf_handoff_jump`
* **Address:** `0xFFFF000062F0C108`
* **Description:** Cleans caches, disables the EL3 MMU, and executes a direct physical branch into ARM Trusted Firmware (BL31) at `0x48200000`.

---

## 2. Android Exception Engine (`aee`) — Sub-Image 2

* **Offset inside `lk.img`:** `0x125E80`
* **Size:** 741,608 bytes
* **Domain / Execution Level:** Non-Secure EL1
* **Load Virtual Address:** `0xFFFF000063F00000`

`aee` is an LK-derived diagnostic subsystem dedicated to crash post-mortems and kernel panic preservation (`kedump`).

### Functions & Memory Structures

#### `kedump_init`
* **Address:** `0xFFFF000063F01000`
* **Description:** Initializes exception engine memory pools in SRAM and DRAM, parses the `expdb` partition header on UFS, and registers panic handlers.

#### Crash Log Storage (`expdb`)
* When the kernel panics or the hardware watchdog trips, the AEE engine stores `last_kmsg` / `console-ramoops` into the raw `expdb` partition.
* Offset `0x3000` in `expdb` holds structured crash diagnostic records.
