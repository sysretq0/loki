# pl_map.r2 — Radare2 Analysis Script for MediaTek Preloader (BL2 / AArch32)
# Target: ADVAN X1 (Firmware Baseline v5)
# Usage: r2 -i pl_map.r2 -B 0x00201000 00_preloader.bin

e asm.arch = arm
e asm.bits = 32
e asm.cpu = cortex-a55
e io.va = true

# Verified Preloader entry point and hardware init symbols
f sym.pl_entry                   = 0x00201000
f sym.main                       = 0x00201634
f sym.usbdl_handler              = 0x00207854
f sym.usbdl_cmd_loop             = 0x00207e3c
f sym.stride_table               = 0x0022aaec
f sym.susbdl_cfg                 = 0x0023aa44

# Seek to Preloader entry
s sym.pl_entry
pdf
