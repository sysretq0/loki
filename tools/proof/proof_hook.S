/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * proof_hook.S — Minimal execution reachability proof hook for MediaTek MT6789 (LK).
 *
 * Demonstrates:
 * 1. expdb marker write to MT6789_WDT_NONRST_REG (0x10007020 = 0xCAFEB007)
 * 2. Onscreen visual text marker via video_set_cursor + video_printf + mt_disp_update
 * 3. Pristine pass-through return to stock execution flow.
 */

.text
.align 2
.global _start
.type _start, %function

_start:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp

    /* 1. Write milestone marker 0xCAFEB007 to NONRST register (0x10007020) */
    mov     x8, #0x7020
    movk    x8, #0x1000, lsl #16
    movk    x8, #0xffff, lsl #48
    mov     w9, #0xB007
    movk    w9, #0xCAFE, lsl #16
    str     w9, [x8]

    /* 2. Position cursor: video_set_cursor(row=4, col=2) */
    mov     w0, #4
    mov     w1, #2
    mov     x8, #0x3B9C
    movk    x8, #0x50F3, lsl #16
    movk    x8, #0xffff, lsl #48    /* 0xFFFF000050F33B9C (video_set_cursor) */
    blr     x8

    /* 3. Print confirmation string: video_printf(msg) */
    adr     x0, proof_msg
    mov     x8, #0x3AD8
    movk    x8, #0x50F3, lsl #16
    movk    x8, #0xffff, lsl #48    /* 0xFFFF000050F33AD8 (video_printf) */
    blr     x8

    /* 4. Update panel scanout: mt_disp_update(0, 0, 1080, 200) */
    mov     w0, wzr
    mov     w1, wzr
    mov     w2, #1080
    mov     w3, #200
    mov     x8, #0x0B88
    movk    x8, #0x50F4, lsl #16
    movk    x8, #0xffff, lsl #48    /* 0xFFFF000050F40B88 (mt_disp_update) */
    blr     x8

    ldp     x29, x30, [sp], #32

    /* 5. Return cleanly to caller */
    ret

.align 3
proof_msg:
    .asciz "[LOKI] HOOK EXECUTION VERIFIED: 0xCAFEB007\n"
