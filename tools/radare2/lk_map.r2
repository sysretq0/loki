# lk_map.r2 — Radare2 Analysis Script for MediaTek Little Kernel (LK / BL33)
# Target: ADVAN X1 (Firmware Baseline v5)
# Usage: r2 -i lk_map.r2 -B 0xffff000050f00000 00_lk.bin

e asm.arch = arm
e asm.bits = 64
e asm.cpu = armv8.2-a
e io.va = true

# Verified function entry point symbols
f sym.lk_entry                   = 0xffff000050f00000
f sym.kmain                      = 0xffff000050f048d8
f sym.thread_init_early          = 0xffff000050f0eb7c
f sym.arch_early_init            = 0xffff000050f038a0
f sym.platform_early_init        = 0xffff000050f0275c
f sym.target_early_init          = 0xffff000050f46374
f sym.heap_init                  = 0xffff000050f56eac
f sym.bootstrap2                 = 0xffff000050f049e4
f sym.target_init                = 0xffff000050f46378
f sym.apps_init                  = 0xffff000050f04a64
f sym.video_printf               = 0xffff000050f33ad8
f sym.video_clean_screen         = 0xffff000050f33be4
f sym.video_set_cursor           = 0xffff000050f33b9c
f sym.mt_disp_update             = 0xffff000050f40b88
f sym.detect_key                 = 0xffff000050f5b940
f sym.fastboot_register          = 0xffff000050f04c5c
f sym.fastboot_publish           = 0xffff000050f04d20
f sym.fastboot_okay              = 0xffff000050f05008
f sym.fastboot_fail              = 0xffff000050f04fe0
f sym.fastboot_info              = 0xffff000050f04f50
f sym.fastboot_stop              = 0xffff000050f0503c
f sym.thread_create              = 0xffff000050f0e21c
f sym.thread_resume              = 0xffff000050f0e23c
f sym.wdt_pet                    = 0xffff000050f33f44
f sym.wdt_set_timeout            = 0xffff000050f33f5c
f sym.platform_halt              = 0xffff000050f15aa8
f sym.bio_open_by_label          = 0xffff000050f55d7c
f sym.bio_close                  = 0xffff000050f55d0c
f sym.bio_read                   = 0xffff000050f55e08
f sym.bio_write                  = 0xffff000050f55e78
f sym.get_suffix                 = 0xffff000050f14690
f sym.set_active                 = 0xffff000050f14ad0
f sym.kernel_decompress          = 0xffff000050f0a994
f sym.cmdline_append             = 0xffff000050f0f800
f sym.fdt_setprop                = 0xffff000050f498e8
f sym.arch_disable_cache         = 0xffff000050f1428c
f sym.arch_clean_cache_disable_mmu_and_jump = 0xffff000050f140e8
f sym.boot_linux                 = 0xffff000050f14330
f sym.smc_boot_linux_trampoline  = 0xffff000050f0c3cc
f sym.malloc                     = 0xffff000050f56fb4
f sym.free                       = 0xffff000050f570e4

# Disassemble kmain by default
s sym.kmain
pdf
