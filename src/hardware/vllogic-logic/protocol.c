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

#include <math.h>
#include <stddef.h>
#include <string.h>

#include "protocol.h"

/* Logical -> physical channel permutation, see la_recv.c:103-106. */
static const int channel_perm[VLLOGIC_NUM_CHANNELS] =
	VLLOGIC_CHANNEL_PERM_INIT;

/**
 * CRC-16/CCITT-FALSE over the 12 on-wire bytes of W1..W3.
 *
 * poly 0x1021, init 0xFFFF, MSB first, no reflection, no final XOR.
 * Source: la_recv.c:136-153.
 */
uint16_t vllogic_crc16(uint32_t w1, uint32_t w2, uint32_t w3)
{
	uint32_t w[3];
	uint16_t crc = 0xFFFF;
	int i, b;

	w[0] = w1;
	w[1] = w2;
	w[2] = w3;

	for (i = 0; i < 12; i++) {
		uint8_t byte = (uint8_t)(w[i >> 2] >> ((i & 3) * 8));

		crc ^= (uint16_t)((uint16_t)byte << 8);
		for (b = 0; b < 8; b++) {
			if (crc & 0x8000)
				crc = (uint16_t)((crc << 1) ^ 0x1021);
			else
				crc = (uint16_t)(crc << 1);
		}
	}

	return crc;
}

/**
 * Build one 16 byte downstream command frame: 4 x u32 LE.
 * w0 = {crc16, 0xC7F3}, w1 = request, w2 = param, w3 = 0.
 * Source: la_recv.c:155-169.
 */
void vllogic_cmd_build(uint8_t out[UHSIF_CMD_SIZE], uint32_t request,
		uint32_t param)
{
	uint32_t w[4];
	int i;

	w[0] = ((uint32_t)vllogic_crc16(request, param, 0) << 16) |
	       UHSIF_CMD_MAGIC16;
	w[1] = request;
	w[2] = param;
	w[3] = 0;

	for (i = 0; i < 4; i++) {
		out[i * 4 + 0] = (uint8_t)(w[i]);
		out[i * 4 + 1] = (uint8_t)(w[i] >> 8);
		out[i * 4 + 2] = (uint8_t)(w[i] >> 16);
		out[i * 4 + 3] = (uint8_t)(w[i] >> 24);
	}
}

/**
 * Build the 32 x 5-bit "next channel" LUT as an ascending ring over the
 * enabled physical channels: first entry is the lowest enabled channel and
 * next[last] wraps around to it.  The FPGA resets the LUT to all zeroes, so a
 * non-ascending ring would repeat channel 0 in every snapshot.
 * Source: la_recv.c:171-205.
 */
void vllogic_lut_build(uint32_t mask, uint32_t lut[5])
{
	uint8_t raw[VLLOGIC_NUM_CHANNELS];
	uint8_t next[VLLOGIC_LUT_ENTRIES];
	int have = 0, first = 0, last = 0;
	int ch, entry, bit_pos, byte_idx, bit_off;

	memset(raw, 0, sizeof(raw));
	memset(next, 0, sizeof(next));

	for (ch = 0; ch < VLLOGIC_NUM_CHANNELS; ch++) {
		if (!(mask & (1u << ch)))
			continue;
		if (!have)
			first = ch;
		else
			next[last] = (uint8_t)ch;
		last = ch;
		have++;
	}

	if (!have) {
		memset(lut, 0, 5 * sizeof(uint32_t));
		return;
	}
	next[last] = (uint8_t)first;

	for (entry = 0; entry < VLLOGIC_LUT_ENTRIES; entry++) {
		unsigned int val = (unsigned int)next[entry] & 0x1Fu;

		bit_pos = entry * 5;
		byte_idx = bit_pos / 8;
		bit_off = bit_pos % 8;

		raw[byte_idx] |= (uint8_t)(val << bit_off);
		if (bit_off > 3 && byte_idx + 1 < VLLOGIC_NUM_CHANNELS)
			raw[byte_idx + 1] |= (uint8_t)(val >> (8 - bit_off));
	}

	for (entry = 0; entry < 5; entry++) {
		lut[entry] = (uint32_t)raw[entry * 4] |
			     ((uint32_t)raw[entry * 4 + 1] << 8) |
			     ((uint32_t)raw[entry * 4 + 2] << 16) |
			     ((uint32_t)raw[entry * 4 + 3] << 24);
	}
}

/**
 * Map the enabled logical channels onto physical ISERDES lanes.
 *
 * The wire snapshot contains one 32-bit word per *enabled physical* lane, in
 * ascending physical order, so the map keeps that order in phys_list[].
 * Source: la_recv.c:1479-1529 (selftest_parser deinterleave setup).
 *
 * @return 0 on success, -1 on invalid input (no channels, bad index, duplicate).
 */
int vllogic_map_build(const int *logical, int nlogical,
		struct vllogic_map *map)
{
	uint32_t mask = 0;
	int i, ch, maxlog = -1;

	if (!map || nlogical <= 0 || nlogical > VLLOGIC_NUM_CHANNELS)
		return -1;

	memset(map, 0, sizeof(*map));
	for (i = 0; i < VLLOGIC_NUM_CHANNELS; i++)
		map->phys2log[i] = -1;

	for (i = 0; i < nlogical; i++) {
		ch = logical[i];
		if (ch < 0 || ch >= VLLOGIC_NUM_CHANNELS)
			return -1;
		if (mask & (1u << channel_perm[ch]))
			return -1;	/* duplicate channel */
		mask |= 1u << channel_perm[ch];
		if (ch > maxlog)
			maxlog = ch;
	}

	map->mask = mask;
	map->unitsize = maxlog / 8 + 1;

	for (ch = 0; ch < VLLOGIC_NUM_CHANNELS; ch++) {
		if (!(mask & (1u << ch)))
			continue;
		map->phys_list[map->nchan++] = ch;
		for (i = 0; i < nlogical; i++) {
			if (channel_perm[logical[i]] == ch) {
				map->phys2log[ch] = (int8_t)logical[i];
				break;
			}
		}
		if (map->phys2log[ch] < 0)
			return -1;
	}

	return 0;
}

/**
 * Measured comparator threshold model (calibrated 2026-10):
 *   Vth = 2.405 - 0.0402 * pwm0 + 0.0216 * pwm1   [V]
 *
 * The old V/3.3*127.5 formula is wrong: SET 1.6 V used to write pwm0 = 62,
 * which actually produces Vth ~= -0.09 V.
 */
double vllogic_pwm_to_vth(unsigned int pwm0, unsigned int pwm1)
{
	return 2.405 - 0.0402 * (double)pwm0 + 0.0216 * (double)pwm1;
}

/*
 * Round a DAC value, reject anything that does not fit into 8 bits.
 * 255.5 would round to 256 and wrap to 0 in the uint8_t assignment, so the
 * upper bound is exclusive.  Non-finite values are rejected explicitly:
 * isfinite() also rules out NaN, for which every comparison is false.
 */
static int pwm_round(double v)
{
	if (!isfinite(v))
		return -1;
	if (v < -0.5 || v >= (double)VLLOGIC_PWM_MAX + 0.5)
		return -1;
	return (int)(v + 0.5);
}

/**
 * Inverse of vllogic_pwm_to_vth().
 *
 * The branch is selected by the sign of the requested threshold first
 * (Vth >= 0 -> pwm0 branch, Vth < 0 -> pwm1 branch), and the other branch is
 * used when the selected one cannot represent the value inside the 8-bit DAC
 * range.  Without that fallback the sign rule alone can never reach the
 * negative part of the documented -2.5 V .. +5.0 V range, because the pwm1
 * coefficient is positive; the measured endpoint mapping (pwm0 = 122 for
 * -2.5 V, pwm1 = 120 for +5.0 V) is reproduced by the feasibility fallback.
 *
 * @return 0 on success, -1 if the value cannot be represented.
 */
int vllogic_vth_to_pwm(double vth, uint8_t *pwm0, uint8_t *pwm1)
{
	double a = (2.405 - vth) / 0.0402;	/* pwm1 = 0 branch */
	double b = (vth - 2.405) / 0.0216;	/* pwm0 = 0 branch */
	int va = pwm_round(a);
	int vb = pwm_round(b);
	int primary, fallback, use_a;

	if (!pwm0 || !pwm1)
		return -1;

	if (vth >= 0.0) {
		primary = va;
		fallback = vb;
		use_a = 1;
	} else {
		primary = vb;
		fallback = va;
		use_a = 0;
	}

	if (primary < 0) {
		if (fallback < 0)
			return -1;
		primary = fallback;
		use_a = !use_a;
	}

	if (use_a) {
		*pwm0 = (uint8_t)primary;
		*pwm1 = 0;
	} else {
		*pwm0 = 0;
		*pwm1 = (uint8_t)primary;
	}

	return 0;
}
