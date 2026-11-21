/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * payload/core/loki_ops.h — Platform abstraction interface for Loki Stage-1 cave.
 */

#pragma once

#include "types.h"

struct loki_display_ops {
	void (*clear)(void);
	void (*set_cursor)(int row, int col);
	int  (*printf)(const char *fmt, ...);
	void (*flush)(void);
};

enum loki_key {
	LOKI_KEY_NONE = 0,
	LOKI_KEY_VOL_DOWN,
	LOKI_KEY_VOL_UP,
	LOKI_KEY_POWER,
};

struct loki_input_ops {
	bool (*is_key_pressed)(enum loki_key key);
};

struct loki_timer_ops {
	void (*mdelay)(u32 ms);
};

struct loki_wdt_ops {
	void (*pet)(void);
	void (*set_timeout)(u32 seconds);
};

struct loki_slot_ops {
	const char *(*get_suffix)(void);
	int (*set_active)(const char *suffix);
};

#define LOKI_BOOT_MODE_NORMAL	0

struct loki_boot_ops {
	void (*set_boot_mode)(u32 mode);
	int  (*boot_chainload)(void);
};

struct loki_security_ops {
	void (*unlock_devapc)(void);
};

struct loki_platform_ops {
	const char              *title;
	struct loki_display_ops  display;
	struct loki_input_ops    input;
	struct loki_timer_ops    timer;
	struct loki_wdt_ops      wdt;
	struct loki_slot_ops     slot;
	struct loki_boot_ops     boot;
	struct loki_security_ops security;
};

extern const struct loki_platform_ops * const g_platform_ops;
