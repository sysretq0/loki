/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * payload/core/lk_provider.c — Stock Little Kernel bindings & subpartition
 * bare-metal chainloader for Loki.
 */

#include "loki_ops.h"
#include "device_config.h"

/* Assembly helpers in arch/arm64/entry.S */
extern int  lk_video_printf(const char *fmt, ...);
extern void arch_mmu_off_jump(u64 entry_phys, u64 arg0, u64 arg1);

/* Stock LK function typedefs */
typedef void  (*lk_video_clean_screen_fn)(void);
typedef void  (*lk_video_set_cursor_fn)(int row, int col);
typedef void  (*lk_mt_disp_update_fn)(int x, int y, int w, int h);
typedef int   (*lk_detect_key_fn)(u16 keycode);
typedef const char *(*lk_get_suffix_fn)(void);
typedef int   (*lk_set_active_fn)(const char *suffix);
typedef void  (*lk_set_boot_mode_fn)(u32 mode);
typedef void *(*lk_bio_open_fn)(const char *name);
typedef ssize (*lk_bio_read_fn)(void *dev, void *buf, u64 offset, usize len);
typedef void  (*lk_bio_close_fn)(void *dev);
typedef void  (*lk_arch_disable_cache_fn)(u32 flags);

#define MKIMG_MAGIC		0x58881688U
#define MKIMG_HDR_SZ		512U

#define LOKI_SUBPART_OFFSET	0x210000ULL
#define LOKI_SUBPART_MAGIC	0x494B4F4CU	/* "LOKI" */
#define CHAINLOAD_PHYS_BASE	0x60000000ULL
#define CHAINLOAD_VIRT_BASE	0xFFFF000060000000ULL
#define CHAINLOAD_MAX_SIZE	0x1E0000ULL	/* 1.875 MiB (fits in 0x210000..0x400000) */

#define MTK_WDT_RESTART_KEY	0x1971U
#define MTK_WDT_LENGTH_KEY	0x0008U
#define MTK_WDT_MODE_KEY	0x22000000U
#define MTK_WDT_MODE_EN_RST	0x7DU

#define LK_VIRT_OFFSET		0xFFFF000000000000ULL
#define WDT_MODE_VIRT		(MT6789_WDT_MODE + LK_VIRT_OFFSET)
#define WDT_LENGTH_VIRT		(MT6789_WDT_LENGTH + LK_VIRT_OFFSET)
#define WDT_RESTART_VIRT	(MT6789_WDT_RESTART + LK_VIRT_OFFSET)
#define DEVAPC_APC_CON_VIRT	(MT6789_DEVAPC_APC_CON + LK_VIRT_OFFSET)
#define OVL0_L0_ADDR_VIRT	(MT6789_DISP_OVL0_BASE + 0xF40ULL + LK_VIRT_OFFSET)

struct loki_subpart_header {
	u32 magic;		/* 0x494B4F4C "LOKI" */
	u32 version;		/* 3 */
	u32 flags;
	u32 payload_off;	/* Relative to this header (0x40) */
	u32 payload_sz;
	u32 extra_off;
	u32 extra_sz;
	u32 crc32;		/* IEEE 802.3 CRC32 of payload bytes */
	u8  reserved[32];
};

static u32 calc_crc32(const u8 *data, usize len)
{
	u32 crc = 0xFFFFFFFFU;

	for (usize i = 0; i < len; i++) {
		crc ^= data[i];
		for (int b = 0; b < 8; b++)
			crc = (crc >> 1) ^ (0xEDB88320U & (u32)(-(s32)(crc & 1U)));
	}
	return ~crc;
}

static void lk_display_clear(void)
{
	((lk_video_clean_screen_fn)ADDR_LK_VIDEO_CLEAN_SCREEN)();
}

static void lk_display_set_cursor(int row, int col)
{
	((lk_video_set_cursor_fn)ADDR_LK_VIDEO_SET_CURSOR)(row, col);
}

static void lk_display_flush(void)
{
	((lk_mt_disp_update_fn)ADDR_LK_MT_DISP_UPDATE)(0, 0, DISPLAY_WIDTH, DISPLAY_HEIGHT);
}

static bool lk_input_is_key_pressed(enum loki_key key)
{
	u16 code = 0;

	switch (key) {
	case LOKI_KEY_VOL_DOWN:
		code = KEY_VOL_DOWN;
		break;
	case LOKI_KEY_VOL_UP:
		code = KEY_VOL_UP;
		break;
	case LOKI_KEY_POWER:
		code = KEY_POWER;
		break;
	default:
		return false;
	}
	return (((lk_detect_key_fn)ADDR_LK_DETECT_KEY)(code) != 0);
}

static void lk_timer_mdelay(u32 ms)
{
	u64 frq, start, target, cur;

	if (!ms)
		return;

	__asm__ volatile ("mrs %0, cntfrq_el0" : "=r" (frq));
	__asm__ volatile ("mrs %0, cntpct_el0" : "=r" (start));
	target = start + (frq / 1000ULL) * (u64)ms;

	do {
		__asm__ volatile ("mrs %0, cntpct_el0" : "=r" (cur));
	} while (cur < target);
}

static void lk_wdt_pet(void)
{
	*(volatile u32 *)(uptr)WDT_RESTART_VIRT = MTK_WDT_RESTART_KEY;
}

static void lk_wdt_set_timeout(u32 seconds)
{
	u32 count = seconds * 64U;

	if (count > 2047U)
		count = 2047U;
	if (count == 0U)
		count = 1U;

	*(volatile u32 *)(uptr)WDT_LENGTH_VIRT = ((count << 5) & 0xFFE0U) | MTK_WDT_LENGTH_KEY;
	*(volatile u32 *)(uptr)WDT_RESTART_VIRT = MTK_WDT_RESTART_KEY;
	*(volatile u32 *)(uptr)WDT_MODE_VIRT = MTK_WDT_MODE_KEY | MTK_WDT_MODE_EN_RST;
}

static const char *lk_slot_get_suffix(void)
{
	return ((lk_get_suffix_fn)ADDR_LK_GET_SUFFIX)();
}

static int lk_slot_set_active(const char *suffix)
{
	return ((lk_set_active_fn)ADDR_LK_SET_ACTIVE)(suffix);
}

static void lk_boot_set_boot_mode(u32 mode)
{
	((lk_set_boot_mode_fn)ADDR_LK_SET_BOOT_MODE)(mode);
}

static void lk_security_unlock_devapc(void)
{
	*(volatile u32 *)(uptr)DEVAPC_APC_CON_VIRT = 0U;
}

static int lk_boot_chainload(void)
{
	lk_bio_open_fn  fn_open  = (lk_bio_open_fn)ADDR_LK_BIO_OPEN_BY_LABEL;
	lk_bio_read_fn  fn_read  = (lk_bio_read_fn)ADDR_LK_BIO_READ;
	lk_bio_close_fn fn_close = (lk_bio_close_fn)ADDR_LK_BIO_CLOSE;
	lk_arch_disable_cache_fn fn_disable_cache =
		(lk_arch_disable_cache_fn)ADDR_LK_ARCH_DISABLE_CACHE;

	const char *slot = lk_slot_get_suffix();
	const char *parts[3] = {
		(slot && slot[1] == 'b') ? "lk_b" : "lk_a",
		(slot && slot[1] == 'b') ? "lk_a" : "lk_b",
		"lk",
	};

	void *bdev = NULL;
	for (int i = 0; i < 3; i++) {
		bdev = fn_open(parts[i]);
		if (bdev)
			break;
	}
	if (!bdev)
		return -2;

	u8 hdr_buf[MKIMG_HDR_SZ];
	u64 hdr_off = LOKI_SUBPART_OFFSET;

	if (fn_read(bdev, hdr_buf, hdr_off, MKIMG_HDR_SZ) != (ssize)MKIMG_HDR_SZ) {
		fn_close(bdev);
		return -3;
	}

	u32 magic = *(u32 *)hdr_buf;
	if (magic == MKIMG_MAGIC) {
		hdr_off += MKIMG_HDR_SZ;
		if (fn_read(bdev, hdr_buf, hdr_off, sizeof(struct loki_subpart_header)) !=
		    (ssize)sizeof(struct loki_subpart_header)) {
			fn_close(bdev);
			return -4;
		}
		magic = *(u32 *)hdr_buf;
	}

	if (magic != LOKI_SUBPART_MAGIC) {
		fn_close(bdev);
		return -5;
	}

	struct loki_subpart_header hdr = *(struct loki_subpart_header *)hdr_buf;
	if (hdr.payload_sz == 0 || hdr.payload_sz > CHAINLOAD_MAX_SIZE) {
		fn_close(bdev);
		return -6;
	}

	u64 payload_off = hdr_off + hdr.payload_off;
	u8 *dst = (u8 *)(uptr)CHAINLOAD_VIRT_BASE;

	lk_display_set_cursor(18, 4);
	lk_video_printf("[*] Loading U-Boot (%u bytes) -> 0x60000000...\n", hdr.payload_sz);
	lk_display_flush();
	lk_wdt_pet();

	ssize rd = fn_read(bdev, dst, payload_off, hdr.payload_sz);
	fn_close(bdev);
	if (rd != (ssize)hdr.payload_sz)
		return -7;

	/* Verify payload integrity before tearing down MMU */
	if (hdr.crc32 != 0U) {
		u32 actual_crc = calc_crc32(dst, hdr.payload_sz);
		if (actual_crc != hdr.crc32)
			return -8;
	}

	/* Clean loaded payload lines from D-cache to PoC */
	for (u64 p = CHAINLOAD_VIRT_BASE; p < CHAINLOAD_VIRT_BASE + hdr.payload_sz; p += 64ULL)
		__asm__ volatile ("dc cvac, %0" :: "r" (p) : "memory");
	__asm__ volatile ("dsb sy\n isb\n" ::: "memory");

	/* Query live OVL0 scanout framebuffer physical base */
	u32 live_fb = *(volatile u32 *)(uptr)OVL0_L0_ADDR_VIRT;
	if (live_fb < 0xFE000000U || live_fb > 0xFF800000U)
		live_fb = (u32)FRAMEBUFFER_PHYS_0;

	/* Arm 60s watchdog safety net before bare-metal jump */
	lk_wdt_set_timeout(60);
	lk_wdt_pet();

	/* Flush & disable caches via stock LK primitive before MMU teardown */
	fn_disable_cache(3);

	/* Never returns: disables MMU and branches to physical 0x60000000 */
	arch_mmu_off_jump(CHAINLOAD_PHYS_BASE, (u64)live_fb, 0);

	return 0;
}

static const struct loki_platform_ops s_platform_ops_lk = {
	.title = DEVICE_TITLE,
	.display = {
		.clear      = lk_display_clear,
		.set_cursor = lk_display_set_cursor,
		.printf     = lk_video_printf,
		.flush      = lk_display_flush,
	},
	.input = {
		.is_key_pressed = lk_input_is_key_pressed,
	},
	.timer = {
		.mdelay = lk_timer_mdelay,
	},
	.wdt = {
		.pet         = lk_wdt_pet,
		.set_timeout = lk_wdt_set_timeout,
	},
	.slot = {
		.get_suffix = lk_slot_get_suffix,
		.set_active = lk_slot_set_active,
	},
	.boot = {
		.set_boot_mode  = lk_boot_set_boot_mode,
		.boot_chainload = lk_boot_chainload,
	},
	.security = {
		.unlock_devapc = lk_security_unlock_devapc,
	},
};

const struct loki_platform_ops * const g_platform_ops = &s_platform_ops_lk;
