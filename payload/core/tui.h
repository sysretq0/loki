/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * payload/core/tui.h — Minimal 3-option Stage-1 boot menu.
 */

#pragma once

#include "types.h"

enum menu_action {
	ACTION_BOOT_SYSTEM = 0,
	ACTION_BOOT_UBOOT,
	ACTION_SWITCH_SLOT,
	ACTION_COUNT
};

void tui_init(void);
void tui_draw(int selected_index, const char *slot_suffix, int auto_boot_sec);
enum menu_action tui_run(void);
