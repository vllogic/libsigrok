/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2026 VLLogic driver authors
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

/*
 * VLLogic "Logic20" logic analyzer, UHSIF v2.2.
 *
 * This header is deliberately free of glib/libusb/libsigrok dependencies so
 * that the protocol helpers and the UHSIF parser can be compiled into the
 * standalone self test binary (see selftest.c).
 *
 * Frame layout, command words and the upstream block header follow
 * /home/llp/h7p20_ch417_proj/logic_analyzer/__test/la_recv.c:60-111 and the
 * if.sigrok description of UHSIF v2.2.  Logic20 (bcdDevice 0x0820) is NOT
 * protocol compatible with the USB Sniffer 2 firmware (bcdDevice 0x0602).
 */

#ifndef LIBSIGROK_HARDWARE_VLLOGIC_LOGIC_PROTOCOL_H
#define LIBSIGROK_HARDWARE_VLLOGIC_LOGIC_PROTOCOL_H

#include <stdint.h>

#define LOG_PREFIX "vllogic-logic"

/* -- Device identity ------------------------------------------------------ */

#define VLLOGIC_VID			0x1209
#define VLLOGIC_PID			0x6688
#define VLLOGIC_BCD_LOGIC20		0x0820
#define VLLOGIC_BCD_SNIFFER2		0x0602
#define VLLOGIC_PRODUCT_LOGIC20		"Logic20"
#define VLLOGIC_IFACE			0
#define VLLOGIC_EP_OUT			0x01
#define VLLOGIC_EP_IN			0x81

/* -- Channel topology ----------------------------------------------------- */

#define VLLOGIC_NUM_CHANNELS		20
#define VLLOGIC_LUT_ENTRIES		32

/* Logical connector channel -> physical ISERDES channel.
 * Source: la_recv.c:103-106 (CHANNEL_PERM, T2i 2026-10-28). */
#define VLLOGIC_CHANNEL_PERM_INIT { \
	1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, \
	16, 17, 18, 19 }

/* Sample clock, ISERDES divider range. Rate = clock / div. */
#define VLLOGIC_CLOCK_HZ		2400000000ull
#define VLLOGIC_DIV_MIN			2
#define VLLOGIC_DIV_MAX			120

/* -- UHSIF wire format ---------------------------------------------------- */

#define UHSIF_CMD_SIZE			16
#define UHSIF_HDR_SIZE			16
#define UHSIF_CMD_MAGIC16		0xC7F3u
#define UHSIF_BLK_MAGIC16		0x6CC6u
#define UHSIF_PAY_MIN			120
#define UHSIF_PAY_MAX			4092
#define UHSIF_DEFAULT_PAYLOAD		4092

/* Downstream command numbers (word 1 of a command frame). */
enum uhsif_cmd {
	UHSIF_CMD_PING			= 0x00,
	UHSIF_CMD_START			= 0x01,
	UHSIF_CMD_STOP			= 0x02,
	UHSIF_CMD_FLUSH			= 0x03,
	UHSIF_CMD_MODE_NORMAL		= 0x04,
	UHSIF_CMD_MODE_WAVE		= 0x05,
	UHSIF_CMD_MODE_COUNTER		= 0x06,
	UHSIF_CMD_CHANNEL_MASK		= 0x10,
	UHSIF_CMD_ISERDES_DIV		= 0x20,
	UHSIF_CMD_VCO			= 0x21,
	UHSIF_CMD_MAX_PAYLOAD		= 0x22,
	UHSIF_CMD_VBIAS_PWM0		= 0x30,
	UHSIF_CMD_VBIAS_PWM1		= 0x31,
	UHSIF_CMD_LUT0			= 0x40,
};

/* -- Analogue threshold (measured, do NOT use V/3.3*127.5) ---------------- */

#define VLLOGIC_PWM_DEFAULT0		19	/* ~1.65 V */
#define VLLOGIC_PWM_DEFAULT1		0
#define VLLOGIC_PWM_MAX			255

/* -- Channel map ---------------------------------------------------------- */

/** Result of mapping the enabled logical channels onto the wire format. */
struct vllogic_map {
	uint32_t mask;			/**< Physical channel bitmask. */
	int nchan;			/**< Number of enabled physical lanes. */
	int unitsize;			/**< Bytes per sample in SR_DF_LOGIC. */
	int phys_list[VLLOGIC_NUM_CHANNELS];	/**< Ascending physical lanes. */
	int8_t phys2log[VLLOGIC_NUM_CHANNELS];	/**< Physical lane -> logical. */
};

/* -- Pure protocol helpers (protocol.c) ----------------------------------- */

uint16_t vllogic_crc16(uint32_t w1, uint32_t w2, uint32_t w3);
void vllogic_cmd_build(uint8_t out[UHSIF_CMD_SIZE], uint32_t request,
		uint32_t param);
void vllogic_lut_build(uint32_t mask, uint32_t lut[5]);
int vllogic_map_build(const int *logical, int nlogical,
		struct vllogic_map *map);
double vllogic_pwm_to_vth(unsigned int pwm0, unsigned int pwm1);
int vllogic_vth_to_pwm(double vth, uint8_t *pwm0, uint8_t *pwm1);

#endif
