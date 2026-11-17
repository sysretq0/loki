# lk_map.r2 — Radare2 Analysis Script for MediaTek Little Kernel (LK / BL33)
# Usage: r2 -i tools/radare2/lk_map.r2 -B 0xffff000050f00000 00_lk.bin

e asm.arch = arm
e asm.bits = 64
e asm.cpu = armv8.2-a
e io.va = true

# Flag known symbols for ADVAN X1 v5 baseline
f sym.lk_entry                   = 0xffff000050f00000
f sym.kmain                      = 0xffff000050f048d8
f sym.bootstrap2                 = 0xffff000050f049e4
f sym.target_init                = 0xffff000050f04a2c
f sym.apps_init                  = 0xffff000050f04a40
f sym.dead_emmc_init_call        = 0xffff000050f0253c
f sym.cave_base                  = 0xffff000050f239c0

f sym.video_clean_screen         = 0xffff000050f089e4
f sym.video_set_cursor           = 0xffff000050f08b34
f sym.video_printf               = 0xffff000050f08b9c
f sym.mt_disp_update             = 0xffff000050f33a9c

f sym.detect_key                 = 0xffff000050f04b30
f sym.bio_open                   = 0xffff000050f16688
f sym.bio_read                   = 0xffff000050f166c8
f sym.bio_close                  = 0xffff000050f16730

f sym.fastboot_register          = 0xffff000050f07bd4
f sym.fastboot_okay              = 0xffff000050f07c68
f sym.fastboot_fail              = 0xffff000050f07c8c
f sym.fastboot_entry_ptr         = 0xffff000050f99a80

f sym.wdt_set_timeout            = 0xffff000050f04ca8
f sym.wdt_pet                    = 0xffff000050f04cd8
f sym.platform_halt              = 0xffff000050f0419c

f sym.get_suffix                 = 0xffff000050f14690
f sym.set_active                 = 0xffff000050f146c4
f sym.kernel_decompress          = 0xffff000050f0bd58
f sym.cmdline_append             = 0xffff000050f0f800
f sym.arch_disable_cache         = 0xffff000050f1428c
f sym.arch_disable_mmu_jump      = 0xffff000050f140e8
f sym.boot_linux                 = 0xffff000050f14330
f sym.smc_boot_linux_trampoline  = 0xffff000050f0c3cc

# Initial disassembly view
s sym.kmain
pdf
