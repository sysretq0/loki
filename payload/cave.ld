/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * payload/cave.ld — Linker script for Stage-1 cave payload inside dead eMMC code.
 */

#include "device_config.h"

ENTRY(loki_cave_entry)

SECTIONS
{
	. = LOKI_CAVE_ADDR;

	.text : {
		*(.text.entry)
		*(.text .text.*)
	}

	.rodata : ALIGN(8) {
		*(.rodata .rodata.*)
	}

	.data : ALIGN(8) {
		*(.data .data.*)
	}

	.bss (NOLOAD) : ALIGN(8) {
		*(.bss .bss.*)
		*(COMMON)
	}

	_cave_end = .;
	ASSERT((_cave_end - LOKI_CAVE_ADDR) <= LOKI_CAVE_SIZE,
	       "ERROR: Loki cave payload exceeds dead-code cave size!")

	/DISCARD/ : {
		*(.comment)
		*(.note*)
		*(.eh_frame*)
	}
}
