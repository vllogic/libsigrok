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

#ifndef LIBSIGROK_HARDWARE_VLLOGIC_LOGIC_VLLOGIC_H
#define LIBSIGROK_HARDWARE_VLLOGIC_LOGIC_VLLOGIC_H

#include <stdint.h>
#include <stdatomic.h>
#include <glib.h>
#include <libusb.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#include "protocol.h"
#include "uhsif_rx.h"

/* 16 x 256 KiB IN URBs, double buffered, see la_recv.c:95-101. */
#define VLLOGIC_URB_COUNT		16
#define VLLOGIC_URB_SIZE		(256 * 1024)
#define VLLOGIC_BUF_COUNT		(2 * VLLOGIC_URB_COUNT)

/*
 * Expanded sample chunks handed from the parser to the session thread.
 * 256 x 64 KiB (16 MiB) absorbs the initial burst of VLLOGIC_URB_COUNT
 * in-flight URBs (16 x 256 KiB = 4 MiB) plus scheduling jitter at 60 MB/s.
 * 64 chunks (4 MiB) used to overflow right at START and drop the tail.
 */
#define VLLOGIC_CHUNK_SIZE		(64 * 1024)
#define VLLOGIC_CHUNK_COUNT		256

/* Upper bound of bytes pushed into one datafeed packet per timer tick. */
#define VLLOGIC_SEND_BUDGET		(4 * 1024 * 1024)

/*
 * Periodic source interval, in ms (must be a negative-key session source).
 * 1 ms keeps the delivered-sample timestamp close to the real capture
 * window; the send budget is per tick, so this also lowers chunk latency.
 */
#define VLLOGIC_POLL_MS			1

/* Drain window after STOP before the URBs get cancelled. */
#define VLLOGIC_DRAIN_MS		200

#define VLLOGIC_ACK_TIMEOUT_MS		10
#define VLLOGIC_ACK_READS		20
#define VLLOGIC_CMD_RETRIES		3

enum vllogic_state {
	VLLOGIC_IDLE = 0,
	VLLOGIC_CAPTURING,
	VLLOGIC_STOPPING,
};

struct vllogic_rx;

struct dev_context {
	struct vllogic_rx *rx;
	libusb_context *usb_ctx;

	struct vllogic_map map;
	uint64_t samplerate;		/**< Output rate (after decimation). */
	uint64_t limit_samples;		/**< Output samples, 0 = unlimited. */
	uint64_t samples_sent;

	uint32_t div;			/**< Hardware ISERDES divider. */
	uint32_t decimate;		/**< PC decimation, 1/2/4/8/20. */
	uint8_t pwm0;
	uint8_t pwm1;

	atomic_int state;		/* set from the session thread, polled by dev_close() */
	int64_t stop_deadline_us;
	int64_t start_us;
	uint64_t last_drop_events;
	uint64_t measured_bps;		/**< link probe result, valid if bw_measured */
	gboolean bw_measured;
	gboolean strict;		/**< VLLOGIC_STRICT != 0 (default 1) */
};

/* -- vllogic_usb.c -------------------------------------------------------- */

struct vllogic_rx *vllogic_rx_new(const struct sr_dev_inst *sdi,
		const struct vllogic_map *map, uint64_t limit_samples);
void vllogic_rx_free(struct vllogic_rx *rx);
int vllogic_rx_start(struct vllogic_rx *rx);
void vllogic_rx_set_stopping(struct vllogic_rx *rx);
void vllogic_rx_stop(struct vllogic_rx *rx);
int vllogic_config_device(struct vllogic_rx *rx, const struct dev_context *devc);
int vllogic_send_simple(struct vllogic_rx *rx, uint32_t cmd, uint32_t param);
size_t vllogic_rx_pop(struct vllogic_rx *rx, const uint8_t **data);
void vllogic_rx_release(struct vllogic_rx *rx);
void vllogic_rx_get_stats(struct vllogic_rx *rx, struct uhsif_stats *stats,
		uint64_t *dropped_chunks);
int vllogic_rx_fatal(struct vllogic_rx *rx);
uint64_t vllogic_rx_samples_produced(const struct vllogic_rx *rx);
uint64_t vllogic_rx_drop_events(const struct vllogic_rx *rx);
int vllogic_probe_link(struct vllogic_rx *rx, unsigned int window_ms,
		uint64_t *bps);
uint64_t vllogic_rx_blocks(const struct vllogic_rx *rx);
int vllogic_rx_first_block_bad(const struct vllogic_rx *rx, char *buf,
		size_t buflen);

#endif
