/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * payload/core/main.c — Minimal Loki Stage-1 entry point.
 *
 * Stealth by default: when Volume Down is not held, returns immediately to
 * stock Little Kernel with zero overhead. When Volume Down is held, presents
 * the 3-option TUI (Boot System, Boot U-Boot subpartition, Switch Slot).
 */

#include "loki_ops.h"
#include "tui.h"

int loki_main(void)
{
	if (!g_platform_ops->input.is_key_pressed(LOKI_KEY_VOL_DOWN))
		return 0;

	if (g_platform_ops->security.unlock_devapc)
		g_platform_ops->security.unlock_devapc();

	for (;;) {
		enum menu_action choice = tui_run();

		switch (choice) {
		case ACTION_BOOT_SYSTEM:
			if (g_platform_ops->boot.set_boot_mode)
				g_platform_ops->boot.set_boot_mode(LOKI_BOOT_MODE_NORMAL);
			return 0;

		case ACTION_BOOT_UBOOT:
			if (g_platform_ops->boot.boot_chainload) {
				int rc = g_platform_ops->boot.boot_chainload();
				/* Only returns on subpartition read/CRC failure */
				g_platform_ops->display.set_cursor(18, 4);
				g_platform_ops->display.printf("[!] Chainload failed (err=%d); returning to menu...\n", rc);
				g_platform_ops->display.flush();
				for (int i = 0; i < 100; i++) {
					g_platform_ops->wdt.pet();
					g_platform_ops->timer.mdelay(20);
				}
			}
			break;

		default:
			return 0;
		}
	}
}
