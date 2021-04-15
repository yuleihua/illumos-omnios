/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Toomas Soome <tsoome@me.com>
 * Copyright 2020 RackTop Systems, Inc.
 */

#ifndef _GFX_FB_H
#define	_GFX_FB_H

#include <stdbool.h>
#include <sys/visual_io.h>
#include <sys/multiboot2.h>
#include <sys/queue.h>
#include <pnglite.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	EDID_MAGIC	{ 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 }

struct edid_header {
	uint8_t header[8];	/* fixed header pattern */
	uint16_t manufacturer_id;
	uint16_t product_code;
	uint32_t serial_number;
	uint8_t week_of_manufacture;
	uint8_t year_of_manufacture;
	uint8_t version;
	uint8_t revision;
};

struct edid_basic_display_parameters {
	uint8_t video_input_parameters;
	uint8_t max_horizontal_image_size;
	uint8_t max_vertical_image_size;
	uint8_t display_gamma;
	uint8_t supported_features;
};

struct edid_chromaticity_coordinates {
	uint8_t red_green_lo;
	uint8_t blue_white_lo;
	uint8_t red_x_hi;
	uint8_t red_y_hi;
	uint8_t green_x_hi;
	uint8_t green_y_hi;
	uint8_t blue_x_hi;
	uint8_t blue_y_hi;
	uint8_t white_x_hi;
	uint8_t white_y_hi;
};

struct edid_detailed_timings {
	uint16_t pixel_clock;
	uint8_t horizontal_active_lo;
	uint8_t horizontal_blanking_lo;
	uint8_t horizontal_hi;
	uint8_t vertical_active_lo;
	uint8_t vertical_blanking_lo;
	uint8_t vertical_hi;
	uint8_t horizontal_sync_offset_lo;
	uint8_t horizontal_sync_pulse_width_lo;
	uint8_t vertical_sync_lo;
	uint8_t sync_hi;
	uint8_t horizontal_image_size_lo;
	uint8_t vertical_image_size_lo;
	uint8_t image_size_hi;
	uint8_t horizontal_border;
	uint8_t vertical_border;
	uint8_t features;
};

struct vesa_edid_info {
	struct edid_header header;
	struct edid_basic_display_parameters display;
#define	EDID_FEATURE_PREFERRED_TIMING_MODE	(1 << 1)
	struct edid_chromaticity_coordinates chromaticity;
	uint8_t established_timings_1;
	uint8_t established_timings_2;
	uint8_t manufacturer_reserved_timings;
	uint16_t standard_timings[8];
	struct edid_detailed_timings detailed_timings[4];
	uint8_t number_of_extensions;
	uint8_t checksum;
} __packed;

extern struct vesa_edid_info *edid_info;

#define	STD_TIMINGS	8
#define	DET_TIMINGS	4

#define	HSIZE(x)	(((x & 0xff) + 31) * 8)
#define	RATIO(x)	((x & 0xC000) >> 14)
#define	RATIO1_1	0
/* EDID Ver. 1.3 redefined this */
#define	RATIO16_10	RATIO1_1
#define	RATIO4_3	1
#define	RATIO5_4	2
#define	RATIO16_9	3

/*
 * Number of pixels and lines is 12-bit int, valid values 0-4095.
 */
#define	EDID_MAX_PIXELS	4095
#define	EDID_MAX_LINES	4095

#define	GET_EDID_INFO_WIDTH(edid_info, timings_num) \
	((edid_info)->detailed_timings[(timings_num)].horizontal_active_lo | \
	(((uint_t)(edid_info)->detailed_timings[(timings_num)].horizontal_hi & \
	0xf0) << 4))

#define	GET_EDID_INFO_HEIGHT(edid_info, timings_num) \
	((edid_info)->detailed_timings[(timings_num)].vertical_active_lo | \
	(((uint_t)(edid_info)->detailed_timings[(timings_num)].vertical_hi & \
	0xf0) << 4))

struct resolution {
	uint32_t width;
	uint32_t height;
	TAILQ_ENTRY(resolution) next;
};

typedef TAILQ_HEAD(edid_resolution, resolution) edid_res_list_t;

extern multiboot_tag_framebuffer_t gfx_fb;

typedef enum {
	GfxFbBltVideoFill,
	GfxFbBltVideoToBltBuffer,
	GfxFbBltBufferToVideo,
	GfxFbBltVideoToVideo,
	GfxFbBltOperationMax,
} GFXFB_BLT_OPERATION;

int gfxfb_blt(void *, GFXFB_BLT_OPERATION, uint32_t, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

void bios_text_font(bool);
bool gfx_get_edid_resolution(struct vesa_edid_info *, edid_res_list_t *);
void gfx_framework_init(void);
uint32_t gfx_fb_color_map(uint8_t);
int gfx_fb_cons_clear(struct vis_consclear *);
void gfx_fb_cons_copy(struct vis_conscopy *);
void gfx_fb_cons_display(struct vis_consdisplay *);
void gfx_fb_display_cursor(struct vis_conscursor *);
void gfx_fb_setpixel(uint32_t, uint32_t);
void gfx_fb_drawrect(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_term_drawrect(uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_fb_line(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
void gfx_fb_bezier(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
	uint32_t);
void plat_cons_update_mode(int);

#define	FL_PUTIMAGE_BORDER	0x1
#define	FL_PUTIMAGE_NOSCROLL	0x2
#define	FL_PUTIMAGE_DEBUG	0x80

int gfx_fb_putimage(png_t *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

bool gfx_parse_mode_str(char *, int *, int *, int *);
#ifdef __cplusplus
}
#endif

#endif /* _GFX_FB_H */
