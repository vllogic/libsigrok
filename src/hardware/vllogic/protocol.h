/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2016 Talpa Chen <talpachen@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_VLLOGIC_PROTOCOL_H
#define LIBSIGROK_HARDWARE_VLLOGIC_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX					"vllogic"

#define VLLOGIC_VID					0xb58a
#define VL1602XX_PID				0xc200

#define VLLOGIC_INTERFACE			0
#define VLLOGIC_IN_EP				1
#define VLLOGIC_OUT_EP				1
#define USB_TIMEOUT_MS				100
#define BULK_IN_TRANSFERS_NUM		32

struct vllogic_in_pkt_info_t
{
	uint32_t pkt_size;
	uint32_t logic_unitcount;
	uint32_t logic_unitchs;
	uint32_t logic_unitbits;
	uint32_t osc_unitchs;
	uint32_t osc_unitbits;
};

struct lpc43xx_registers_list_t
{
	// read only area
	uint32_t version;
#define VLLOGIC_VERSION_SCHEME_LPC43XX		(43 << 24)
#define VLLOGIC_BOARD_VL1602ED				(1 << 16)
#define VLLOGIC_BOARD_VL1602				(2 << 16)

	uint32_t board_in_channels_mask;
	uint32_t board_out_channels_mask;

	uint32_t status_mask;
#define VLLOGIC_STATUS_NOP					0
#define VLLOGIC_STATUS_CMD_ERROR			(0x1ul << 0)
#define VLLOGIC_STATUS_CONFIG_DONE			(0x1ul << 1)
#define VLLOGIC_STATUS_CAPTURE_OVERFLOW		(0x1ul << 2)
#define VLLOGIC_STATUS_CAPTURE_DONE			(0x1ul << 3)

	// read write area
	uint32_t command;
#define VLLOGIC_CMD_NOP						0
#define VLLOGIC_CMD_DONE					1
#define VLLOGIC_CMD_START					0x10000000
#define VLLOGIC_CMD_STOP					0x10000001
#define VLLOGIC_CMD_CONFIG					0x10000002

	uint32_t mode;
#define VLLOGIC_MODE_NOP					0
#define VLLOGIC_MODE_IN						(0x1 << 0)
#define VLLOGIC_MODE_OUT					(0x1 << 1)

	// channel parameter
	uint32_t rate;

	/*
	bit			function
	[0, 15] 	digital channels enable mask
	[16, 17]	analog channels enable mask
	*/
	uint32_t channels_in_enable_mask;

	/*
	bit			function
	[0, 15] 	low level trigger enable mask
	[16, 32]	high level trigger enable mask
	*/
	uint32_t digital_channels_level_trigger_mask;

	/*
	bit			function
	[0, 15] 	falling edge trigger enable mask
	[16, 32]	rising edge trigger enable mask
	*/
	uint32_t digital_channels_edge_trigger_mask;

	/*
	bit			function
	[0, 15] 	digital channels enable mask
	[16, 17]	analog channels enable mask
	*/
	uint32_t channels_out_enable_mask;

	// read only area
	struct vllogic_in_pkt_info_t in_pkt_info;
};


enum vllogic_registers_series_t
{
	VLLOGIC_REGISTERS_SERIES_LPC43XX = 0,
};

struct vllogic_profile_t
{
	uint16_t vid;
	uint16_t pid;

	enum vllogic_registers_series_t type;
};

struct dev_context
{
	char vendor[16];
	char model[16];

	enum vllogic_registers_series_t type;

	struct lpc43xx_registers_list_t lpc43xx_registers;

	//gboolean continuous_mode;
	gboolean trigger_fired;
	gboolean acq_aborted;

	int64_t cur_samplerate;
	int64_t limit_samples;
	int64_t sent_samples;

	int empty_transfer_count;
	
	int32_t submitted_transfers;
	struct libusb_transfer *transfers[BULK_IN_TRANSFERS_NUM];
	size_t transferbuffer_size;
	uint8_t *convbuffer;
	size_t convbuffer_size;


	uint16_t digital_channel_masks[16];

	uint32_t digital_channel_select_mask;
	uint32_t digital_channel_select_num;
	uint32_t digital_channel_num;

	uint32_t analog_channel_select_mask;
	uint32_t analog_channel_select_num;
	uint32_t analog_channel_num;

	size_t (*convert_sample)(struct dev_context *devc,
		uint8_t *dest, size_t destcnt, const uint8_t *src, size_t srccnt);	
	struct sr_context *ctx;
};

SR_PRIV struct dev_context *vll_new_device(struct drv_context *drvc, struct sr_usb_dev_inst *usb);
SR_PRIV int vll_start_acquisition(const struct sr_dev_inst *sdi);
SR_PRIV int vll_config_acquisition(const struct sr_dev_inst *sdi);
SR_PRIV int vll_stop_acquisition(const struct sr_dev_inst *sdi);

#endif // LIBSIGROK_HARDWARE_VLLOGIC_PROTOCOL_H

