/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * payload/arch/arm64/entry.S — Stage-1 cave trampoline & MMU-off handoff.
 */

#include "device_config.h"

.section .text.entry, "ax"
.global loki_cave_entry
loki_cave_entry:
	b	.Lstage1_trampoline

.Lstage1_trampoline:
	stp	x29, x30, [sp, #-32]!
	mov	x29, sp
	stp	x19, x20, [sp, #16]

	/* 1. Execute hijacked stock target_init() (UFS + GPT + keypad online) */
	ldr	x8, =ADDR_LK_TARGET_INIT
	blr	x8

	/* 2. Run Loki Stage-1 stealth check / TUI menu */
	bl	loki_main

	/* 3. Resume stock Little Kernel normally */
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #32
	ret

/* Direct tail-call shim to stock LK video_printf */
.global lk_video_printf
lk_video_printf:
	ldr	x8, =ADDR_LK_VIDEO_PRINTF
	br	x8

/*
 * void arch_mmu_off_jump(u64 entry_phys, u64 arg0, u64 arg1)
 *
 * Masks DAIF, pivots from LK's higher-half VA into low physical identity PC,
 * disables MMU / D-cache / I-cache, invalidates TLB + I-cache, and branches
 * directly to the standalone payload (e.g. U-Boot _start at 0x60000000).
 *
 * Deliberately preserves one-shot ATF SMC MTK_SIP_KERNEL_BOOT_AARCH64 so
 * U-Boot retains full ATF BL31 SiP and PSCI services.
 */
.global arch_mmu_off_jump
.type arch_mmu_off_jump, %function
arch_mmu_off_jump:
	msr	daifset, #0xf
	isb

	mov	x19, x0		/* physical entry point */
	mov	x20, x1		/* arg0 (live FB base) */
	mov	x21, x2		/* arg1 (reserved) */

	mrs	x3, CurrentEL
	ubfx	x3, x3, #2, #2
	cmp	x3, #2
	b.eq	.Lhand_el2

	/* ---- EL1 pivot via TTBR0 identity map ---- */
	mrs	x9, sctlr_el1
	bic	x9, x9, #(1 << 19)	/* Clear WXN */
	msr	sctlr_el1, x9
	isb

	ldr	x9, =0x2b5107516
	msr	tcr_el1, x9
	isb

	adr	x4, .Lphys_mmu_off
	uxtw	x4, w4
	br	x4

.Lhand_el2:
	/* ---- EL2 pivot ---- */
	mrs	x9, sctlr_el2
	bic	x9, x9, #(1 << 19)
	msr	sctlr_el2, x9
	isb

	adr	x4, .Lphys_mmu_off
	uxtw	x4, w4
	br	x4

.Lphys_mmu_off:
	mrs	x3, CurrentEL
	ubfx	x3, x3, #2, #2
	cmp	x3, #2
	b.eq	.Loff_el2

	mrs	x9, sctlr_el1
	bic	x9, x9, #(1 << 0)	/* M: MMU off */
	bic	x9, x9, #(1 << 2)	/* C: D-cache off */
	bic	x9, x9, #(1 << 12)	/* I: I-cache off */
	msr	sctlr_el1, x9
	isb

	tlbi	vmalle1
	dsb	sy
	isb
	ic	iallu
	dsb	sy
	isb
	b	.Ljump_target

.Loff_el2:
	mrs	x9, sctlr_el2
	bic	x9, x9, #(1 << 0)
	bic	x9, x9, #(1 << 2)
	bic	x9, x9, #(1 << 12)
	msr	sctlr_el2, x9
	isb

	tlbi	alle2
	dsb	sy
	isb
	ic	iallu
	dsb	sy
	isb

.Ljump_target:
	mov	x0, x20
	mov	x1, x21
	mov	x2, xzr
	mov	x3, xzr
	br	x19
.size arch_mmu_off_jump, . - arch_mmu_off_jump
