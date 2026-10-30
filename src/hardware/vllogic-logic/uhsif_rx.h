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
 * UHSIF v2.2 upstream parser and de-interleaver.
 *
 * Free of glib/libusb/libsigrok dependencies, so it can be exercised without
 * any hardware by the vllogic-selftest binary.
 *
 * The state machine below is a port of the verified implementation in
 * /home/llp/h7p20_ch417_proj/logic_analyzer/__test/la_recv.c:612-796
 * (parser_word/parser_header/parser_feed_raw/parser_feed) and
 * la_recv.c:575-611 (emit_snapshot).
 */

#ifndef LIBSIGROK_HARDWARE_VLLOGIC_LOGIC_UHSIF_RX_H
#define LIBSIGROK_HARDWARE_VLLOGIC_LOGIC_UHSIF_RX_H

#include <stddef.h>
#include <stdint.h>

#include "protocol.h"

/** Parser / link statistics, see la_recv.c:649-707. */
struct uhsif_stats {
	uint64_t blocks;		/**< All CRC-valid blocks. */
	uint64_t acks;			/**< Blocks with payload_len == 0. */
	uint64_t data_blocks;		/**< Blocks carrying samples. */
	uint64_t crc_fail;		/**< Headers rejected by the CRC. */
	uint64_t bad_len;		/**< payload_len outside [120, 4092]. */
	uint64_t seq_jumps;		/**< Seq byte did not increment. */
	uint64_t drop_blocks;		/**< Data blocks with W2[22] set. */
	uint64_t junk_bytes;		/**< Bytes skipped while scanning. */
	uint64_t mask_mismatch;		/**< W1 mask != configured mask. */
	uint64_t payload_words;		/**< 32-bit words accepted. */
	uint64_t partial_snapshots;	/**< Snapshots cut by STOP / resync. */
	uint64_t sink_short;		/**< Snapshots the sink only partly took. */
	uint64_t sink_short_bytes;	/**< Bytes of those snapshots dropped. */
};

/** Downstream sink for expanded samples, called from the parser. */
struct uhsif_sink {
	/**
	 * Consume expanded samples (whole snapshots, multiple of unitsize).
	 * @return number of bytes accepted; the parser drops the remainder.
	 */
	size_t (*write)(void *user, const uint8_t *data, size_t len);
	/**
	 * Flush any partially filled output buffer at end of stream.
	 * Optional; may be NULL.
	 */
	void (*flush)(void *user);
};

/** Parser state machine (SCAN / HDR / PAY), see la_recv.c:709-796. */
struct uhsif_parser {
	int state;			/**< 0 = scan, 1 = header, 2 = payload. */
	uint8_t hdr[UHSIF_HDR_SIZE];
	unsigned int hdr_len;
	uint8_t carry[UHSIF_HDR_SIZE];	/**< <= 3 data bytes / <= 15 hdr bytes. */
	unsigned int carry_len;
	uint32_t pay_rem;
	uint32_t snap[VLLOGIC_NUM_CHANNELS];
	int snap_pos;
	const struct vllogic_map *map;

	/** PC decimation: keep one out of every @a decimate input samples. */
	unsigned int decimate;
	unsigned int dec_phase;

	/** Bytes to rescan before the current input, see parser_header(). */
	uint8_t replay[UHSIF_HDR_SIZE];
	unsigned int replay_len;

	uint64_t limit_samples;		/**< 0 = unlimited. */
	uint64_t samples_out;		/**< Output samples after decimation. */
	int limit_reached;

	/* Decoded fields of the most recent valid header. */
	uint32_t hdr_mask;
	unsigned int hdr_div;
	unsigned int hdr_mode;
	unsigned int hdr_vco;
	unsigned int hdr_drop;
	unsigned int hdr_capturing;

	int drop_active;		/**< Previous block's drop flag. */
	uint8_t last_seq;
	int have_seq;

	struct uhsif_stats st;

	const struct uhsif_sink *sink;
	void *sink_user;

	uint64_t expand8[256];		/**< Bit spread table, see la_recv.c:611. */
};

void uhsif_parser_init(struct uhsif_parser *p, const struct vllogic_map *map,
		uint64_t limit_samples, unsigned int decimate,
		const struct uhsif_sink *sink, void *sink_user);
void uhsif_parser_feed(struct uhsif_parser *p, const uint8_t *data, size_t len);
/**
 * Enable dropping the leading (pre-START pipeline) payload word.
 * Call right after uhsif_parser_init(), before any data is fed.
 */
/** Flush at end of stream; counts a truncated snapshot if one is pending. */
void uhsif_parser_finish(struct uhsif_parser *p);

/** Run the built-in self test (no hardware access). 0 = PASS. */
int uhsif_selftest(int verbose);

#endif
