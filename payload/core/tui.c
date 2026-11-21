/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * payload/core/tui.c — Minimal interactive boot menu (Boot / Chainload / Slot).
 */

#include "tui.h"
#include "loki_ops.h"

static const char * const s_menu_labels[ACTION_COUNT] = {
	[ACTION_BOOT_SYSTEM] = "BOOT SYSTEM        (Continue Stock Android)",
	[ACTION_BOOT_UBOOT]  = "BOOT U-BOOT        (Chainload LK Subpartition)",
	[ACTION_SWITCH_SLOT] = "SWITCH SLOT        (Toggle Active A/B Slot)",
};

static inline u32 get_current_el(void)
{
	u64 el;

	__asm__ volatile ("mrs %0, CurrentEL" : "=r" (el));
	return (u32)((el >> 2) & 3);
}

static void print_banner(void)
{
	const char *title = (g_platform_ops && g_platform_ops->title)
			    ? g_platform_ops->title : "MediaTek";

	g_platform_ops->display.set_cursor(2, 2);
	g_platform_ops->display.printf("==========================================================\n");
	g_platform_ops->display.set_cursor(3, 2);
	g_platform_ops->display.printf("                  _       _    _                          \n");
	g_platform_ops->display.set_cursor(4, 2);
	g_platform_ops->display.printf("                 | |     | |  (_)                         \n");
	g_platform_ops->display.set_cursor(5, 2);
	g_platform_ops->display.printf("                 | | ___ | | ___                          \n");
	g_platform_ops->display.set_cursor(6, 2);
	g_platform_ops->display.printf("                 | |/ _ \\| |/ / |                         \n");
	g_platform_ops->display.set_cursor(7, 2);
	g_platform_ops->display.printf("                 | | (_) |   <| |                         \n");
	g_platform_ops->display.set_cursor(8, 2);
	g_platform_ops->display.printf("                 |_|\\___/|_|\\_\\_|                         \n");
	g_platform_ops->display.set_cursor(9, 2);
	g_platform_ops->display.printf("==========================================================\n");
	g_platform_ops->display.set_cursor(10, 2);
	g_platform_ops->display.printf(" Loki Chainloader: %s | EL%d\n", title, get_current_el());
	g_platform_ops->display.set_cursor(11, 2);
	g_platform_ops->display.printf("==========================================================\n");
}

void tui_init(void)
{
	g_platform_ops->display.clear();
	g_platform_ops->display.flush();
}

static void tui_draw_footer(const char *slot_suffix, int auto_boot_sec)
{
	g_platform_ops->display.set_cursor(20, 2);
	g_platform_ops->display.printf("----------------------------------------------------------\n");
	g_platform_ops->display.set_cursor(21, 2);
	if (auto_boot_sec > 0) {
		g_platform_ops->display.printf(" [ Slot: %s | EL%d | Auto-boot: %2ds (Any key to hold) ]  \n",
					       slot_suffix ? slot_suffix : "unknown",
					       get_current_el(),
					       auto_boot_sec);
	} else {
		g_platform_ops->display.printf(" [ Slot: %s | EL%d | Interactive (WDT: Active) ]          \n",
					       slot_suffix ? slot_suffix : "unknown",
					       get_current_el());
	}
	g_platform_ops->display.set_cursor(22, 2);
	g_platform_ops->display.printf(" [ VolUp/VolDown: Navigate | Power: Select ]              \n");
	g_platform_ops->display.set_cursor(23, 2);
	g_platform_ops->display.printf("==========================================================\n");
}

static void tui_update_countdown(const char *slot_suffix, int auto_boot_sec)
{
	g_platform_ops->display.set_cursor(21, 2);
	if (auto_boot_sec > 0) {
		g_platform_ops->display.printf(" [ Slot: %s | EL%d | Auto-boot: %2ds (Any key to hold) ]  \n",
					       slot_suffix ? slot_suffix : "unknown",
					       get_current_el(),
					       auto_boot_sec);
	} else {
		g_platform_ops->display.printf(" [ Slot: %s | EL%d | Interactive (WDT: Active) ]          \n",
					       slot_suffix ? slot_suffix : "unknown",
					       get_current_el());
	}
	g_platform_ops->display.flush();
}

void tui_draw(int selected_index, const char *slot_suffix, int auto_boot_sec)
{
	g_platform_ops->display.clear();
	print_banner();

	for (int i = 0; i < ACTION_COUNT; i++) {
		g_platform_ops->display.set_cursor(14 + i, 4);
		const char *sel = (i == selected_index) ? " > [*] " : "   [ ] ";

		if (i == ACTION_SWITCH_SLOT) {
			g_platform_ops->display.printf("%sSWITCH SLOT        (Active: %s -> Toggle)\n",
						       sel, slot_suffix ? slot_suffix : "_a");
		} else {
			g_platform_ops->display.printf("%s%s\n", sel, s_menu_labels[i]);
		}
	}

	tui_draw_footer(slot_suffix, auto_boot_sec);
	g_platform_ops->display.flush();
}

enum menu_action tui_run(void)
{
	int selected = ACTION_BOOT_UBOOT;
	const char *slot = "_a";

	if (g_platform_ops->slot.get_suffix) {
		slot = g_platform_ops->slot.get_suffix();
		if (!slot)
			slot = "_a";
	}

	int auto_boot_sec = 10;
	int tick_count = 0;

	g_platform_ops->wdt.set_timeout(60);
	g_platform_ops->wdt.pet();

	tui_init();
	tui_draw(selected, slot, auto_boot_sec);

	/* Wait for Volume Down release before accepting navigation events */
	while (g_platform_ops->input.is_key_pressed(LOKI_KEY_VOL_DOWN)) {
		g_platform_ops->wdt.pet();
		g_platform_ops->timer.mdelay(20);
	}

	u32 prev_keys = 0;

	for (;;) {
		g_platform_ops->wdt.pet();
		g_platform_ops->timer.mdelay(20);

		if (auto_boot_sec > 0) {
			tick_count++;
			if (tick_count >= 50) {
				tick_count = 0;
				auto_boot_sec--;
				tui_update_countdown(slot, auto_boot_sec);
				if (auto_boot_sec <= 0)
					return ACTION_BOOT_SYSTEM;
			}
		}

		u32 up   = g_platform_ops->input.is_key_pressed(LOKI_KEY_VOL_UP);
		u32 down = g_platform_ops->input.is_key_pressed(LOKI_KEY_VOL_DOWN);
		u32 pw   = g_platform_ops->input.is_key_pressed(LOKI_KEY_POWER);

		u32 event = 0;
		if (!(prev_keys & 1u) && up)
			event = 1;
		else if (!(prev_keys & 2u) && down)
			event = 2;
		else if (!(prev_keys & 4u) && pw)
			event = 3;

		prev_keys = (up ? 1u : 0u) | (down ? 2u : 0u) | (pw ? 4u : 0u);

		if (event != 0 && auto_boot_sec > 0) {
			auto_boot_sec = 0;
			tui_update_countdown(slot, 0);
		}

		if (event == 1) {
			selected = (selected - 1 + ACTION_COUNT) % ACTION_COUNT;
			tui_draw(selected, slot, 0);
		} else if (event == 2) {
			selected = (selected + 1) % ACTION_COUNT;
			tui_draw(selected, slot, 0);
		} else if (event == 3) {
			while (g_platform_ops->input.is_key_pressed(LOKI_KEY_POWER)) {
				g_platform_ops->wdt.pet();
				g_platform_ops->timer.mdelay(20);
			}

			if (selected == ACTION_SWITCH_SLOT) {
				const char *next = (slot && slot[1] == 'a') ? "_b" : "_a";

				if (g_platform_ops->slot.set_active)
					g_platform_ops->slot.set_active(next);
				if (g_platform_ops->slot.get_suffix) {
					slot = g_platform_ops->slot.get_suffix();
					if (!slot)
						slot = next;
				} else {
					slot = next;
				}
				tui_draw(selected, slot, 0);
				continue;
			}

			return (enum menu_action)selected;
		}
	}
}
