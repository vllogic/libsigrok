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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uhsif_rx.h"

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

static uint32_t rd32le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * UHSIF upstream block header word bitfields (RTL rev 2026-10).
 * Source: la_recv.c:625-647.
 *
 *   W2[7:0]   = v_bias_pwm1
 *   W2[21:15] = iserdes_clk_div[6:0]
 *   W2[22]    = drop_flag   (FIFO dropped a snapshot)
 *   W2[23]    = capturing
 *   W2[31:24] = lut_chk8
 *
 *   W3[7:0]   = v_bias_pwm0
 *   W3[9:8]   = vco_select[1:0]
 *   W3[11:10] = mode[1:0]
 *   W3[23:12] = payload_len
 *   W3[31:24] = seq
 */
#define HDR_W2_PWM1(w2)		((uint32_t)(w2) & 0xFFu)
#define HDR_W2_DIV(w2)		(((uint32_t)(w2) >> 15) & 0x7Fu)
#define HDR_W2_DROP(w2)		(((uint32_t)(w2) >> 22) & 1u)
#define HDR_W2_CAPTURING(w2)	(((uint32_t)(w2) >> 23) & 1u)
#define HDR_W2_LUT_CHK8(w2)	(((uint32_t)(w2) >> 24) & 0xFFu)
#define HDR_W3_PWM0(w3)		((uint32_t)(w3) & 0xFFu)
#define HDR_W3_VCO(w3)		(((uint32_t)(w3) >> 8) & 3u)
#define HDR_W3_MODE(w3)		(((uint32_t)(w3) >> 10) & 3u)
#define HDR_W3_PLEN(w3)		(((uint32_t)(w3) >> 12) & 0xFFFu)
#define HDR_W3_SEQ(w3)		(((uint32_t)(w3) >> 24) & 0xFFu)

/* ------------------------------------------------------------------------- */
/* Parser                                                                    */
/* ------------------------------------------------------------------------- */

/**
 * Expand one snapshot into wire-order sample bytes and hand it to the sink.
 * Port of la_recv.c:575-611 (emit_snapshot), with limit_samples handling.
 */
static void emit_snapshot(struct uhsif_parser *p)
{
	uint64_t lanes[3][4];
	uint8_t lbytes[3][32];
	uint8_t out[3 * 32];
	const struct vllogic_map *map = p->map;
	unsigned int dec = p->decimate ? p->decimate : 1;
	int nchan = map->nchan;
	int unit = map->unitsize;
	int g, k, j, s, lane, bit, emitted = 0;
	uint64_t m;

	if (p->limit_reached)
		return;

	memset(lanes, 0, sizeof(lanes));
	for (g = 0; g < nchan; g++) {
		uint32_t w = p->snap[g];
		int logical = map->phys2log[map->phys_list[g]];

		lane = logical >> 3;
		bit = logical & 7;
		m = (uint64_t)1 << bit;

		for (k = 0; k < 4; k++)
			lanes[lane][k] |=
				p->expand8[(w >> (k * 8)) & 0xFFu] * m;
	}

	for (lane = 0; lane < unit; lane++) {
		for (k = 0; k < 4; k++) {
			uint64_t v = lanes[lane][k];

			for (j = 0; j < 8; j++)
				lbytes[lane][k * 8 + j] =
					(uint8_t)(v >> (j * 8));
		}
	}

	/*
	 * PC decimation happens in the output domain: keep input sample 0,
	 * dec, 2*dec, ... across snapshot boundaries (the phase is carried in
	 * the parser, so factors that do not divide 32 work as well).
	 * limit_samples counts these output samples.
	 */
	for (s = 0; s < 32; s++) {
		if (p->dec_phase != 0) {
			p->dec_phase++;
			if (p->dec_phase >= dec)
				p->dec_phase = 0;
			continue;
		}
		if (p->limit_samples != 0 &&
		    p->samples_out + (uint64_t)emitted >= p->limit_samples) {
			p->limit_reached = 1;
			break;
		}
		{
			uint8_t *o = out + (size_t)emitted * (size_t)unit;

			for (j = 0; j < unit; j++)
				o[j] = lbytes[j][s];
		}
		emitted++;
		p->dec_phase = 1;
		if (p->dec_phase >= dec)
			p->dec_phase = 0;
	}

	if (emitted > 0 && p->sink && p->sink->write) {
		size_t want = (size_t)emitted * (size_t)unit;
		size_t got = p->sink->write(p->sink_user, out, want);

		if (got < want) {
			/*
			 * The chunk layer is behind.  Account only for the
			 * whole samples it accepted; the rest of this
			 * snapshot is dropped as one unit.
			 */
			p->st.sink_short++;
			p->st.sink_short_bytes += (uint64_t)(want - got);
			emitted = (int)(got / (size_t)unit);
		}
	}

	p->samples_out += (uint64_t)emitted;
	if (p->limit_samples != 0 && p->samples_out >= p->limit_samples)
		p->limit_reached = 1;

	/*
	 * The sink coalesces snapshots into large chunks.  When the sample
	 * limit is reached, the session must see the tail now, otherwise it
	 * cannot observe samples_sent >= limit and never initiates STOP.
	 */
	if (p->limit_reached && p->sink && p->sink->flush)
		p->sink->flush(p->sink_user);
}

static void parser_word(struct uhsif_parser *p, uint32_t w)
{
	p->st.payload_words++;
	p->snap[p->snap_pos++] = w;
	if (p->snap_pos == p->map->nchan) {
		p->snap_pos = 0;
		emit_snapshot(p);
	}
}

static void parser_header(struct uhsif_parser *p)
{
	uint32_t w0 = rd32le(p->hdr + 0);
	uint32_t w1 = rd32le(p->hdr + 4);
	uint32_t w2 = rd32le(p->hdr + 8);
	uint32_t w3 = rd32le(p->hdr + 12);
	uint32_t plen = HDR_W3_PLEN(w3);
	uint8_t seq = (uint8_t)HDR_W3_SEQ(w3);

	p->hdr_mask = w1;
	p->hdr_div = HDR_W2_DIV(w2);
	p->hdr_mode = HDR_W3_MODE(w3);
	p->hdr_vco = HDR_W3_VCO(w3);
	p->hdr_drop = HDR_W2_DROP(w2);
	p->hdr_capturing = HDR_W2_CAPTURING(w2);
	(void)HDR_W2_PWM1(w2);
	(void)HDR_W2_LUT_CHK8(w2);
	(void)HDR_W3_PWM0(w3);

	if ((w0 >> 16) != vllogic_crc16(w1, w2, w3)) {
		p->st.crc_fail++;
		/*
		 * The candidate header is corrupt, so the snapshot assembled
		 * so far belongs to it and must not be completed with words
		 * from the next block.  Drop the phase and rescan from the
		 * byte after the first magic byte: the bytes already read as
		 * "header" may contain the real next block header (a false
		 * magic must not swallow it).
		 */
		p->snap_pos = 0;
		p->st.partial_snapshots++;
		p->replay_len = UHSIF_HDR_SIZE - 1;
		memcpy(p->replay, p->hdr + 1, p->replay_len);
		p->state = 0;
		return;
	}

	if (p->have_seq && seq != (uint8_t)(p->last_seq + 1))
		p->st.seq_jumps++;
	p->last_seq = seq;
	p->have_seq = 1;

	p->st.blocks++;

	if (plen == 0) {
		p->st.acks++;
		p->state = 0;
		return;
	}
	if (plen < UHSIF_PAY_MIN || plen > UHSIF_PAY_MAX) {
		p->st.bad_len++;
		p->state = 0;
		return;
	}

	p->st.data_blocks++;
	/*
	 * drop_flag is latched for the capture, not a per-block state, so
	 * count its 0 -> 1 edge instead of every block that carries it.
	 */
	if (p->hdr_drop && !p->drop_active) {
		p->st.drop_blocks++;
		p->drop_active = 1;
	} else if (!p->hdr_drop) {
		p->drop_active = 0;
	}
	if ((w1 & 0xFFFFFu) != p->map->mask)
		p->st.mask_mismatch++;

	p->pay_rem = plen;
	p->state = 2;
}

/**
 * Feed one contiguous chunk.  All state (scan/header/payload) lives in the
 * parser, so this may be called with arbitrarily split buffers.  Only the
 * partial header (<= 15 B) and a partial 32-bit word (<= 3 B) are carried
 * across calls.  Source: la_recv.c:709-770.
 */
static void parser_feed_raw(struct uhsif_parser *p, const uint8_t *data,
		size_t len)
{
	const uint8_t *d = data;
	size_t n = len;

	for (;;) {
		/*
		 * A rejected header left bytes that must be rescanned before
		 * the current input, in stream order.  The replay is at most
		 * 15 bytes and cannot contain a complete header on its own,
		 * so this recursion is bounded.
		 */
		if (p->replay_len > 0) {
			uint8_t tmp[UHSIF_HDR_SIZE];
			unsigned int rl = p->replay_len;

			memcpy(tmp, p->replay, rl);
			p->replay_len = 0;
			parser_feed_raw(p, tmp, (size_t)rl);
			continue;
		}

		if (p->state == 2) {			/* payload */
			while (p->pay_rem > 0 && n >= 4) {
				uint32_t w = rd32le(d);

				d += 4;
				n -= 4;
				p->pay_rem--;
				parser_word(p, w);
			}
			if (p->pay_rem == 0) {
				p->state = 0;
				continue;
			}
			if (n > 0) {
				memcpy(p->carry, d, n);
				p->carry_len = (unsigned int)n;
			}
			return;
		}

		if (p->state == 1) {			/* header */
			size_t want = (size_t)(UHSIF_HDR_SIZE - p->hdr_len);
			size_t take = want > n ? n : want;

			memcpy(p->hdr + p->hdr_len, d, take);
			p->hdr_len += (unsigned int)take;
			d += take;
			n -= take;
			if (p->hdr_len < UHSIF_HDR_SIZE)
				return;
			p->hdr_len = 0;
			parser_header(p);
			continue;
		}

		/* Scan for the block magic, one byte at a time. */
		if (n < 4) {
			if (n > 0) {
				memcpy(p->carry, d, n);
				p->carry_len = (unsigned int)n;
			}
			return;
		}
		if ((rd32le(d) & 0xFFFFu) != UHSIF_BLK_MAGIC16) {
			d++;
			n--;
			p->st.junk_bytes++;
			continue;
		}
		memcpy(p->hdr, d, 4);
		p->hdr_len = 4;
		d += 4;
		n -= 4;
		p->state = 1;
	}
}

void uhsif_parser_feed(struct uhsif_parser *p, const uint8_t *data, size_t len)
{
	size_t off = 0;

	/* Stitch a tiny carry from the previous URB together with new data. */
	while (p->carry_len > 0 && off < len) {
		uint8_t tmp[UHSIF_HDR_SIZE];
		unsigned int cl = p->carry_len;
		size_t take = (size_t)UHSIF_HDR_SIZE - cl;

		if (take > len - off)
			take = len - off;
		memcpy(tmp, p->carry, cl);
		memcpy(tmp + cl, data + off, take);
		p->carry_len = 0;
		parser_feed_raw(p, tmp, (size_t)cl + take);
		off += take;
	}
	if (off < len)
		parser_feed_raw(p, data + off, len - off);
}

void uhsif_parser_finish(struct uhsif_parser *p)
{
	/* STOP truncated a block, so the last snapshot may be incomplete. */
	if (p->snap_pos != 0) {
		p->st.partial_snapshots++;
		p->snap_pos = 0;
	}
	p->carry_len = 0;
	p->hdr_len = 0;
	p->pay_rem = 0;
	p->replay_len = 0;
	p->dec_phase = 0;
	p->drop_active = 0;
	p->state = 0;

	/* Hand the last partially filled output chunk downstream. */
	if (p->sink && p->sink->flush)
		p->sink->flush(p->sink_user);
}

void uhsif_parser_init(struct uhsif_parser *p, const struct vllogic_map *map,
		uint64_t limit_samples, unsigned int decimate,
		const struct uhsif_sink *sink, void *sink_user)
{
	int b, j;

	memset(p, 0, sizeof(*p));
	p->map = map;
	p->limit_samples = limit_samples;
	p->decimate = decimate ? decimate : 1;
	p->sink = sink;
	p->sink_user = sink_user;

	/* Bit spread table: byte -> one bit per 8-byte slot. */
	for (b = 0; b < 256; b++) {
		uint64_t e = 0;

		for (j = 0; j < 8; j++) {
			if (b & (1 << j))
				e |= (uint64_t)1 << (j * 8);
		}
		p->expand8[b] = e;
	}
}

/* ------------------------------------------------------------------------- */
/* Self test (no hardware, no glib, no libusb)                               */
/* ------------------------------------------------------------------------- */

#define ST_MAX_STREAM	(1u << 20)
#define ST_MAX_OUT	(1u << 20)

struct st_ctx {
	uint8_t *out;
	size_t cap;
	size_t len;
};

static size_t st_write(void *user, const uint8_t *data, size_t len)
{
	struct st_ctx *c = user;
	size_t room = c->cap - c->len;
	size_t take = len > room ? room : len;

	memcpy(c->out + c->len, data, take);
	c->len += take;
	return take;
}

static const struct uhsif_sink st_sink = {
	.write = st_write,
};

/* Deterministic pseudo random words, mirrors la_recv.c:1433-1441. */
static uint64_t st_xs = 0x123456789ABCDEFull;

static uint32_t st_rand(void)
{
	st_xs ^= st_xs << 13;
	st_xs ^= st_xs >> 7;
	st_xs ^= st_xs << 17;
	return (uint32_t)(st_xs >> 16);
}

/**
 * Build one upstream block (header + payload), mirroring
 * la_recv.c:1443-1464.  With bad_crc the header CRC is XORed with 0x5A5A.
 */
static size_t st_block(uint8_t *dst, uint32_t mask, uint8_t seq,
		const uint32_t *words, uint32_t plen, uint32_t w2_extra,
		int bad_crc)
{
	uint32_t w1 = mask;
	uint32_t w2 = w2_extra;
	uint32_t w3 = ((uint32_t)seq << 24) | ((plen & 0xFFFu) << 12);
	uint32_t crc = vllogic_crc16(w1, w2, w3);
	uint32_t w0;
	uint32_t i;

	if (bad_crc)
		crc ^= 0x5A5Au;

	w0 = (crc << 16) | UHSIF_BLK_MAGIC16;
	wr32le(dst + 0, w0);
	wr32le(dst + 4, w1);
	wr32le(dst + 8, w2);
	wr32le(dst + 12, w3);
	for (i = 0; i < plen; i++)
		wr32le(dst + 16 + i * 4, words ? words[i] : 0);

	return 16 + (size_t)plen * 4;
}

/* Reference de-interleave, straight from the protocol definition. */
static void st_reference(const struct vllogic_map *map, const uint32_t *words,
		uint32_t nsnap, uint8_t *expect)
{
	size_t e = 0;
	uint32_t i;
	int s, b, g;

	for (i = 0; i < nsnap; i++) {
		for (s = 0; s < 32; s++) {
			for (b = 0; b < map->unitsize; b++)
				expect[e + (size_t)b] = 0;
			for (g = 0; g < map->nchan; g++) {
				uint32_t w = words[i * (uint32_t)map->nchan +
						    (uint32_t)g];
				int logical =
					map->phys2log[map->phys_list[g]];

				if ((w >> s) & 1u)
					expect[e + (size_t)(logical >> 3)] |=
						(uint8_t)(1u << (logical & 7));
			}
			e += (size_t)map->unitsize;
		}
	}
}

struct st_case {
	const char *name;
	int logical[VLLOGIC_NUM_CHANNELS];
	int nlogical;
	int junk;		/**< Prepend garbage bytes. */
	int with_acks;		/**< Interleave ACK blocks. */
	int with_bad_crc;	/**< Inject one CRC-broken header. */
	uint64_t limit;		/**< limit_samples, 0 = unlimited. */
	uint32_t per_block;	/**< Payload words per block, 0 = 120. */
	unsigned int decimate;	/**< PC decimation factor, 0/1 = off. */
};

/**
 * Build a stream, feed it to the parser in the configured chunk sizes and
 * compare the expanded samples against the reference de-interleave.
 *
 * The total number of payload words is chosen as a multiple of both the
 * channel count and UHSIF_PAY_MIN so every block is legal and no snapshot
 * straddles a block boundary - except in the cases that deliberately test
 * cross-block behaviour.
 */
static int st_run_case(const struct st_case *tc, int verbose)
{
	uint8_t *stream = NULL;
	uint8_t *expect = NULL;
	uint32_t *words = NULL;
	struct st_ctx ctx;
	struct uhsif_parser parser;
	struct vllogic_map map;
	uint32_t total_words, nsnap, nblocks, per_block, idx, seq;
	unsigned int dec;
	int bad_done = 0;
	size_t stream_len = 0, off = 0;
	static const size_t chunks[] = { 1, 2, 3, 5, 7, 13, 64, 1000, 4096 };
	const int nchunks = (int)(sizeof(chunks) / sizeof(chunks[0]));
	uint64_t full_samples, out_samples, j;
	int ci = 0, ok = 1, ret = 1;

	memset(&parser, 0, sizeof(parser));
	memset(&ctx, 0, sizeof(ctx));

	if (vllogic_map_build(tc->logical, tc->nlogical, &map) != 0) {
		fprintf(stderr, "  %s: vllogic_map_build() failed\n", tc->name);
		return 1;
	}

	/*
	 * The default is 480 payload words: divisible by 4 blocks and by
	 * 1/2/3/4/6/8 channel counts, and 120 words per block is exactly
	 * UHSIF_PAY_MIN.  Cases may override per_block (e.g. 4092 with 20
	 * channels, which straddles snapshots across block boundaries).
	 */
	per_block = tc->per_block ? tc->per_block : 120;
	nblocks = 4;
	total_words = per_block * nblocks;
	nsnap = total_words / (uint32_t)map.nchan;
	dec = tc->decimate ? tc->decimate : 1;
	if (nsnap == 0) {
		fprintf(stderr, "  %s: bad test geometry\n", tc->name);
		return 1;
	}

	words = calloc((size_t)total_words, sizeof(uint32_t));
	if (!words) {
		fprintf(stderr, "  %s: out of memory\n", tc->name);
		return 1;
	}
	stream = malloc(ST_MAX_STREAM);
	expect = malloc(ST_MAX_OUT);
	ctx.out = malloc(ST_MAX_OUT);
	if (!stream || !expect || !ctx.out) {
		fprintf(stderr, "  %s: out of memory\n", tc->name);
		free(words);
		free(stream);
		free(expect);
		free(ctx.out);
		return 1;
	}
	ctx.cap = ST_MAX_OUT;

	for (idx = 0; idx < total_words; idx++)
		words[idx] = st_rand();

	st_reference(&map, words, nsnap, expect);

	if (tc->junk) {
		int i;

		/* Junk bytes that can never contain the 0x6CC6 magic. */
		for (i = 0; i < 7; i++)
			stream[stream_len++] = (uint8_t)(0x11 + i);
	}

	seq = 0;
	idx = 0;
	while (idx < total_words) {
		uint32_t n = per_block;

		if (idx + n > total_words)
			n = total_words - idx;
		if (tc->with_acks) {
			stream_len += st_block(stream + stream_len, map.mask,
					(uint8_t)seq++, NULL, 0, 0, 0);
		}
		stream_len += st_block(stream + stream_len, map.mask,
				(uint8_t)seq++, words + idx, n, 0, 0);
		idx += n;

		if (tc->with_bad_crc && !bad_done) {
			uint32_t i;

			/*
			 * Magic present, CRC wrong: the parser must reject the
			 * header and resynchronise on the next valid block.
			 * The filler bytes 0x40..0x7f can never alias the
			 * 0x6CC6 magic (0xC6 is out of that range).
			 */
			stream_len += st_block(stream + stream_len, map.mask,
					(uint8_t)seq, NULL, 120, 0, 1);
			bad_done = 1;
			for (i = 0; i < 120 * 4; i++)
				stream[stream_len++] = (uint8_t)(0x40 + (i & 0x3F));
		}
	}

	uhsif_parser_init(&parser, &map, tc->limit, dec, &st_sink, &ctx);

	while (off < stream_len) {
		size_t n = chunks[ci++ % nchunks];

		if (n > stream_len - off)
			n = stream_len - off;
		uhsif_parser_feed(&parser, stream + off, n);
		off += n;
	}
	uhsif_parser_finish(&parser);

	/* --- compare ---------------------------------------------------- */
	if (parser.st.payload_words != total_words) {
		fprintf(stderr, "  %s: words %llu != %u\n", tc->name,
			(unsigned long long)parser.st.payload_words,
			total_words);
		ok = 0;
	}
	if (parser.st.crc_fail != (uint64_t)(tc->with_bad_crc ? 1 : 0)) {
		fprintf(stderr, "  %s: crc_fail %llu\n", tc->name,
			(unsigned long long)parser.st.crc_fail);
		ok = 0;
	}
	if (parser.st.bad_len != 0) {
		fprintf(stderr, "  %s: bad_len %llu\n", tc->name,
			(unsigned long long)parser.st.bad_len);
		ok = 0;
	}
	if (parser.st.seq_jumps != 0) {
		fprintf(stderr, "  %s: seq_jumps %llu\n", tc->name,
			(unsigned long long)parser.st.seq_jumps);
		ok = 0;
	}
	if (parser.st.mask_mismatch != 0) {
		fprintf(stderr, "  %s: mask_mismatch %llu\n", tc->name,
			(unsigned long long)parser.st.mask_mismatch);
		ok = 0;
	}
	if (parser.st.data_blocks != nblocks) {
		fprintf(stderr, "  %s: data_blocks %llu != %u\n", tc->name,
			(unsigned long long)parser.st.data_blocks, nblocks);
		ok = 0;
	}
	if (parser.st.acks != (uint64_t)(tc->with_acks ? nblocks : 0)) {
		fprintf(stderr, "  %s: acks %llu\n", tc->name,
			(unsigned long long)parser.st.acks);
		ok = 0;
	}
	if (tc->junk && parser.st.junk_bytes < 7) {
		fprintf(stderr, "  %s: junk_bytes %llu\n", tc->name,
			(unsigned long long)parser.st.junk_bytes);
		ok = 0;
	}

	full_samples = (uint64_t)nsnap * 32;
	out_samples = (full_samples + dec - 1) / dec;
	if (tc->limit != 0 && tc->limit < out_samples)
		out_samples = tc->limit;
	if (ctx.len != out_samples * (uint64_t)map.unitsize) {
		fprintf(stderr, "  %s: out len %zu != %llu (unit %d)\n",
			tc->name, ctx.len,
			(unsigned long long)(out_samples *
				(uint64_t)map.unitsize), map.unitsize);
		ok = 0;
	} else {
		uint64_t bad = 0;

		for (j = 0; j < out_samples; j++) {
			const uint8_t *e = expect +
				(size_t)(j * dec) * (size_t)map.unitsize;
			const uint8_t *o = ctx.out +
				(size_t)j * (size_t)map.unitsize;

			if (memcmp(o, e, (size_t)map.unitsize) != 0)
				bad++;
		}
		if (bad) {
			fprintf(stderr, "  %s: %llu/%llu samples differ\n",
				tc->name, (unsigned long long)bad,
				(unsigned long long)out_samples);
			ok = 0;
		}
	}
	if (tc->limit != 0 && parser.limit_reached != 1) {
		fprintf(stderr, "  %s: limit not reached\n", tc->name);
		ok = 0;
	}
	if (tc->limit != 0 && parser.samples_out != out_samples) {
		fprintf(stderr, "  %s: samples_out %llu != %llu\n", tc->name,
			(unsigned long long)parser.samples_out,
			(unsigned long long)out_samples);
		ok = 0;
	}

	if (verbose) {
		printf("  %-26s nchan=%2d unit=%d scr=%u hdr=%llu junk=%llu "
		       "crc=%llu ack=%llu: %s\n", tc->name, map.nchan,
		       map.unitsize, total_words,
		       (unsigned long long)parser.st.blocks,
		       (unsigned long long)parser.st.junk_bytes,
		       (unsigned long long)parser.st.crc_fail,
		       (unsigned long long)parser.st.acks,
		       ok ? "ok" : "FAIL");
	}

	ret = ok ? 0 : 1;
	free(words);
	free(stream);
	free(expect);
	free(ctx.out);
	return ret;
}

/* Header bitfield decode check, mirrors la_recv.c:1671-1726. */
static int st_header_bits(int verbose)
{
	struct vllogic_map map;
	struct uhsif_parser parser;
	int logical[1] = { 0 };
	uint32_t w1, w2, w3, w0;
	int ok = 1;

	if (vllogic_map_build(logical, 1, &map) != 0)
		return 1;
	uhsif_parser_init(&parser, &map, 0, 1, NULL, NULL);

	w1 = 0x00001u;
	w2 = (0x5Au << 24) | (1u << 23) | (1u << 22) | (0x2Bu << 15) | 0xC3u;
	w3 = (0x77u << 24) | (120u << 12) | (2u << 10) | (3u << 8) | 0x19u;
	w0 = ((uint32_t)vllogic_crc16(w1, w2, w3) << 16) | UHSIF_BLK_MAGIC16;
	wr32le(parser.hdr + 0, w0);
	wr32le(parser.hdr + 4, w1);
	wr32le(parser.hdr + 8, w2);
	wr32le(parser.hdr + 12, w3);
	parser_header(&parser);

	if (parser.st.data_blocks != 1 || parser.st.drop_blocks != 1 ||
	    parser.hdr_div != 0x2Bu || parser.hdr_mode != 2u ||
	    parser.hdr_vco != 3u || parser.hdr_capturing != 1u ||
	    parser.st.crc_fail != 0) {
		fprintf(stderr, "  header bits: W2 decode mismatch\n");
		ok = 0;
	}

	/* Same length, no drop flag: the drop counter must not move. */
	w2 = (0x00u << 24) | (0u << 22) | (120u << 15);
	w3 = (0x78u << 24) | (120u << 12) | (1u << 10) | (0u << 8);
	w0 = ((uint32_t)vllogic_crc16(w1, w2, w3) << 16) | UHSIF_BLK_MAGIC16;
	wr32le(parser.hdr + 0, w0);
	wr32le(parser.hdr + 8, w2);
	wr32le(parser.hdr + 12, w3);
	parser_header(&parser);
	if (parser.st.drop_blocks != 1 || parser.hdr_div != 120u ||
	    parser.hdr_mode != 1u || parser.hdr_vco != 0u ||
	    parser.hdr_capturing != 0u) {
		fprintf(stderr, "  header bits: div/drop decode mismatch\n");
		ok = 0;
	}

	if (verbose) {
		printf("  %-26s drop=%llu div=%u mode=%u vco=%u: %s\n",
		       "header bitfields",
		       (unsigned long long)parser.st.drop_blocks,
		       parser.hdr_div, parser.hdr_mode, parser.hdr_vco,
		       ok ? "ok" : "FAIL");
	}

	return ok ? 0 : 1;
}

/* LUT vectors, measured expectations from la_recv.c:1418-1431. */
static int st_lut(int verbose)
{
	static const struct {
		uint32_t mask;
		uint32_t lut[5];
	} vectors[] = {
		{ 0x00001u, { 0x00000000u, 0x00000000u, 0x00000000u,
			      0x00000000u, 0x00000000u } },
		{ 0x00020u, { 0x0A000000u, 0x00000000u, 0x00000000u,
			      0x00000000u, 0x00000000u } },
		{ 0x80000u, { 0x00000000u, 0x00000000u, 0x80000000u,
			      0x00000009u, 0x00000000u } },
		{ 0x80021u, { 0x26000005u, 0x00000000u, 0x00000000u,
			      0x00000000u, 0x00000000u } },
		{ 0x00007u, { 0x00000041u, 0x00000000u, 0x00000000u,
			      0x00000000u, 0x00000000u } },
		{ 0xFFFFFu, { 0xCC520C41u, 0xD62D4941u, 0x4E5183DCu,
			      0x00000000u, 0x00000000u } },
	};
	size_t i;
	int k, ok = 1;

	for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		uint32_t lut[5];

		vllogic_lut_build(vectors[i].mask, lut);
		for (k = 0; k < 5; k++) {
			if (lut[k] != vectors[i].lut[k]) {
				fprintf(stderr,
					"  LUT mask=0x%05X word %d: %08X != %08X\n",
					vectors[i].mask, k, lut[k],
					vectors[i].lut[k]);
				ok = 0;
			}
		}
		if (verbose)
			printf("  %-26s mask=0x%05X %08X %08X %08X %08X "
			       "%08X\n", "LUT ascending ring", vectors[i].mask,
			       lut[0], lut[1], lut[2], lut[3], lut[4]);
	}

	return ok ? 0 : 1;
}

/* CRC and threshold model checks. */
static int st_protocol(int verbose)
{
	uint16_t c1 = vllogic_crc16(0x01, 0x01, 0x00);
	uint16_t c2 = vllogic_crc16(0x22, 120, 0x00);
	uint8_t pwm0, pwm1;
	double vth;
	int ok = 1;

	if (c1 != 0xC05F || c2 != 0x4265) {
		fprintf(stderr, "  crc16: %04X/%04X != C05F/4265\n", c1, c2);
		ok = 0;
	}

	/* Default threshold must be ~1.65 V. */
	vth = vllogic_pwm_to_vth(VLLOGIC_PWM_DEFAULT0, VLLOGIC_PWM_DEFAULT1);
	if (vth < 1.5 || vth > 1.8) {
		fprintf(stderr, "  vth default: %.3f\n", vth);
		ok = 0;
	}

	/*
	 * DAC rounding must reject, not wrap: 255.5 would become 256 / 0 and
	 * NaN must not slip through the range comparisons.
	 */
	if (vllogic_vth_to_pwm(2.405 - 0.0402 * 255.5, &pwm0, &pwm1) != -1) {
		fprintf(stderr, "  pwm_round accepted 255.5 (wraps to 0)\n");
		ok = 0;
	}
	if (vllogic_vth_to_pwm(NAN, &pwm0, &pwm1) != -1) {
		fprintf(stderr, "  pwm_round accepted NaN\n");
		ok = 0;
	}

	/* Round trip over the documented range. */
	{
		static const double points[] = { -2.5, -1.0, -0.075, 0.0, 0.8,
						 1.65, 3.0, 5.0 };
		size_t i;

		for (i = 0; i < sizeof(points) / sizeof(points[0]); i++) {
			double got;

			if (vllogic_vth_to_pwm(points[i], &pwm0, &pwm1) != 0) {
				fprintf(stderr, "  vth %.3f not representable\n",
					points[i]);
				ok = 0;
				continue;
			}
			got = vllogic_pwm_to_vth(pwm0, pwm1);
			if (got < points[i] - 0.06 || got > points[i] + 0.06) {
				fprintf(stderr,
					"  vth %.3f -> pwm0=%u pwm1=%u -> %.3f\n",
					points[i], pwm0, pwm1, got);
				ok = 0;
			}
			if (verbose)
				printf("  %-26s %+.3f V -> pwm0=%3u pwm1=%3u "
				       "(%.3f V)\n", "threshold solve",
				       points[i], pwm0, pwm1, got);
		}
	}

	return ok ? 0 : 1;
}

/* Build a complete, CRC-valid 16-byte upstream block header. */
static void st_hdr(uint8_t *dst, uint32_t mask, uint8_t seq, uint32_t plen,
		uint32_t w2_extra)
{
	uint32_t w1 = mask;
	uint32_t w2 = w2_extra;
	uint32_t w3 = ((uint32_t)seq << 24) | ((plen & 0xFFFu) << 12);
	uint32_t crc = vllogic_crc16(w1, w2, w3);

	wr32le(dst + 0, (crc << 16) | UHSIF_BLK_MAGIC16);
	wr32le(dst + 4, w1);
	wr32le(dst + 8, w2);
	wr32le(dst + 12, w3);
}

static void st_feed_chunks(struct uhsif_parser *p, const uint8_t *stream,
		size_t stream_len)
{
	static const size_t chunks[] = { 1, 2, 3, 5, 7, 13, 64, 1000, 4096 };
	const int nchunks = (int)(sizeof(chunks) / sizeof(chunks[0]));
	size_t off = 0;
	int ci = 0;

	while (off < stream_len) {
		size_t n = chunks[ci++ % nchunks];

		if (n > stream_len - off)
			n = stream_len - off;
		uhsif_parser_feed(p, stream + off, n);
		off += n;
	}
	uhsif_parser_finish(p);
}

/*
 * CRC failure with a partial snapshot in flight and a fake valid ACK header
 * inside the rejected block's payload.  The stale snapshot must be dropped,
 * the fake magic must be handled, and the following real block must be
 * decoded from its first sample.
 */
static int st_crc_snap_reset(int verbose)
{
	int logical[20] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
			    14, 15, 16, 17, 18, 19 };
	uint32_t w1[130], w2[128];
	uint8_t *stream, *expect, bad[16], fake[16];
	struct vllogic_map map;
	struct uhsif_parser parser;
	struct st_ctx ctx;
	size_t len = 0;
	uint32_t i;
	int ok = 1;

	if (vllogic_map_build(logical, 20, &map) != 0)
		return 1;

	stream = malloc(ST_MAX_STREAM);
	expect = malloc(ST_MAX_OUT);
	ctx.out = malloc(ST_MAX_OUT);
	ctx.cap = ST_MAX_OUT;
	ctx.len = 0;
	if (!stream || !expect || !ctx.out) {
		free(stream);
		free(expect);
		free(ctx.out);
		return 1;
	}

	for (i = 0; i < 130; i++)
		w1[i] = st_rand();
	for (i = 0; i < 128; i++)
		w2[i] = st_rand();

	/* B1: 130 words -> 6 complete 20-channel snapshots + 10 words. */
	len += st_block(stream + len, map.mask, 0, w1, 130, 0, 0);

	/*
	 * Bad-CRC header, followed by 130 words of payload whose first 16
	 * bytes form a valid ACK block.  A naive resync that swallows the
	 * 16 header bytes or keeps snap_pos would corrupt the next block.
	 */
	st_hdr(bad, map.mask, 1, 130, 0);
	{
		uint32_t bw1 = rd32le(bad + 4);
		uint32_t bw2 = rd32le(bad + 8);
		uint32_t bw3 = rd32le(bad + 12);
		uint16_t bcrc = (vllogic_crc16(bw1, bw2, bw3) == 0) ? 1 : 0;

		wr32le(bad + 0, ((uint32_t)bcrc << 16) | UHSIF_BLK_MAGIC16);
	}
	memcpy(stream + len, bad, 16);
	len += 16;
	st_hdr(fake, map.mask, 1, 0, 0);
	memcpy(stream + len, fake, 16);
	memset(stream + len + 16, 0x11, 130 * 4 - 16);
	len += 130 * 4;

	/* B2: 128 words -> 6 complete snapshots. */
	len += st_block(stream + len, map.mask, 2, w2, 128, 0, 0);

	uhsif_parser_init(&parser, &map, 0, 1, &st_sink, &ctx);
	st_feed_chunks(&parser, stream, len);

	st_reference(&map, w1, 6, expect);
	st_reference(&map, w2, 6, expect + 6 * 32 * (size_t)map.unitsize);

	if (ctx.len != 12 * 32 * (size_t)map.unitsize ||
	    memcmp(ctx.out, expect, ctx.len) != 0) {
		fprintf(stderr, "  crc snap reset: output mismatch (%zu B)\n",
			ctx.len);
		ok = 0;
	}
	if (parser.st.crc_fail != 1 || parser.st.blocks != 3 ||
	    parser.st.data_blocks != 2 || parser.st.acks != 1 ||
	    parser.st.payload_words != 258 || parser.st.seq_jumps != 0 ||
	    parser.st.partial_snapshots != 2 || parser.samples_out != 384) {
		fprintf(stderr, "  crc snap reset: crc=%llu blk=%llu data=%llu "
			"ack=%llu words=%llu seq=%llu part=%llu out=%llu\n",
			(unsigned long long)parser.st.crc_fail,
			(unsigned long long)parser.st.blocks,
			(unsigned long long)parser.st.data_blocks,
			(unsigned long long)parser.st.acks,
			(unsigned long long)parser.st.payload_words,
			(unsigned long long)parser.st.seq_jumps,
			(unsigned long long)parser.st.partial_snapshots,
			(unsigned long long)parser.samples_out);
		ok = 0;
	}

	if (verbose)
		printf("  %-26s crc=%llu blk=%llu part=%llu out=%llu: %s\n",
		       "crc snap reset", (unsigned long long)parser.st.crc_fail,
		       (unsigned long long)parser.st.blocks,
		       (unsigned long long)parser.st.partial_snapshots,
		       (unsigned long long)parser.samples_out,
		       ok ? "ok" : "FAIL");

	free(stream);
	free(expect);
	free(ctx.out);
	return ok ? 0 : 1;
}

/*
 * A real block header starts two bytes into a false magic.  The first 16
 * bytes are consumed as a CRC-broken header; rescanning from one byte after
 * the false magic must still find the real header, which a parser that
 * swallowed all 16 bytes would miss.
 */
static int st_crc_overlap(int verbose)
{
	int logical[20] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
			    14, 15, 16, 17, 18, 19 };
	uint32_t w1[130], w2[128];
	uint8_t *stream, *expect, prefix[18], hdr2[16];
	struct vllogic_map map;
	struct uhsif_parser parser;
	struct st_ctx ctx;
	size_t len = 0;
	uint32_t i, w2x;
	int ok = 1, found = 0;

	if (vllogic_map_build(logical, 20, &map) != 0)
		return 1;

	stream = malloc(ST_MAX_STREAM);
	expect = malloc(ST_MAX_OUT);
	ctx.out = malloc(ST_MAX_OUT);
	ctx.cap = ST_MAX_OUT;
	ctx.len = 0;
	if (!stream || !expect || !ctx.out) {
		free(stream);
		free(expect);
		free(ctx.out);
		return 1;
	}

	for (i = 0; i < 130; i++)
		w1[i] = st_rand();
	for (i = 0; i < 128; i++)
		w2[i] = st_rand();

	len += st_block(stream + len, map.mask, 0, w1, 130, 0, 0);

	/*
	 * prefix = { 0x6CC6, hdr2[0..15] }.  The parser reads the first 16
	 * bytes (false magic + hdr2[0..13]) as one header, whose CRC field
	 * is 0x6CC6; pick a w2 value for which that CRC is wrong.
	 */
	for (w2x = 0; w2x < 16; w2x++) {
		uint32_t bw1, bw2, bw3;

		st_hdr(hdr2, map.mask, 1, 128, w2x << 24);
		prefix[0] = (uint8_t)(UHSIF_BLK_MAGIC16 & 0xFF);
		prefix[1] = (uint8_t)(UHSIF_BLK_MAGIC16 >> 8);
		memcpy(prefix + 2, hdr2, 16);
		bw1 = rd32le(prefix + 4);
		bw2 = rd32le(prefix + 8);
		bw3 = rd32le(prefix + 12);
		if (vllogic_crc16(bw1, bw2, bw3) !=
		    (uint16_t)(rd32le(prefix + 0) >> 16)) {
			found = 1;
			break;
		}
	}
	if (!found) {
		fprintf(stderr, "  crc overlap: could not build bad header\n");
		ok = 0;
		goto out;
	}

	memcpy(stream + len, prefix, sizeof(prefix));
	len += sizeof(prefix);
	{
		size_t n = st_block(stream + len, map.mask, 1, w2, 128, 0, 0);

		/*
		 * st_block() writes its own header; remove it and keep only
		 * the payload.  The real header is already in prefix.
		 */
		memmove(stream + len, stream + len + 16, n - 16);
		len += n - 16;
	}

	uhsif_parser_init(&parser, &map, 0, 1, &st_sink, &ctx);
	st_feed_chunks(&parser, stream, len);

	st_reference(&map, w1, 6, expect);
	st_reference(&map, w2, 6, expect + 6 * 32 * (size_t)map.unitsize);

	if (ctx.len != 12 * 32 * (size_t)map.unitsize ||
	    memcmp(ctx.out, expect, ctx.len) != 0) {
		fprintf(stderr, "  crc overlap: output mismatch (%zu B)\n",
			ctx.len);
		ok = 0;
	}
	if (parser.st.crc_fail != 1 || parser.st.blocks != 2 ||
	    parser.st.data_blocks != 2 || parser.st.acks != 0 ||
	    parser.st.payload_words != 258 || parser.st.seq_jumps != 0 ||
	    parser.st.partial_snapshots != 2 || parser.samples_out != 384) {
		fprintf(stderr, "  crc overlap: crc=%llu blk=%llu data=%llu "
			"ack=%llu words=%llu seq=%llu part=%llu out=%llu\n",
			(unsigned long long)parser.st.crc_fail,
			(unsigned long long)parser.st.blocks,
			(unsigned long long)parser.st.data_blocks,
			(unsigned long long)parser.st.acks,
			(unsigned long long)parser.st.payload_words,
			(unsigned long long)parser.st.seq_jumps,
			(unsigned long long)parser.st.partial_snapshots,
			(unsigned long long)parser.samples_out);
		ok = 0;
	}

	if (verbose)
		printf("  %-26s crc=%llu blk=%llu part=%llu out=%llu: %s\n",
		       "crc overlap resync",
		       (unsigned long long)parser.st.crc_fail,
		       (unsigned long long)parser.st.blocks,
		       (unsigned long long)parser.st.partial_snapshots,
		       (unsigned long long)parser.samples_out,
		       ok ? "ok" : "FAIL");

out:
	free(stream);
	free(expect);
	free(ctx.out);
	return ok ? 0 : 1;
}

/**
 * Built-in self test.  Constructs UHSIF streams, feeds them in small pieces
 * and verifies the expanded sample stream.  Covers:
 *   1. block headers split across feed boundaries,
 *   2. junk bytes before the first header,
 *   3. resynchronisation after a CRC failure,
 *   4. ACK and data blocks interleaved,
 *   5. unitsize 1/2/3 expansion,
 *   6. limit_samples truncation,
 * plus CRC, LUT and threshold vectors.
 *
 * @return 0 if every check passed, 1 otherwise.
 */
struct st_short_ctx {
	size_t budget;
	size_t got;
};

static size_t st_short_write(void *user, const uint8_t *data, size_t len)
{
	struct st_short_ctx *c = user;
	size_t take = len > c->budget ? c->budget : len;

	(void)data;
	c->budget -= take;
	c->got += take;

	return take;
}

/*
 * A sink that stops accepting after a fixed budget must not inflate the
 * sample accounting: samples_out may only count the whole samples the sink
 * actually took, and the loss must be visible in st.sink_short*.
 */
static int st_sink_short(int verbose)
{
	static const int logical[VLLOGIC_NUM_CHANNELS] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19 };
	struct st_short_ctx sc;
	struct uhsif_sink sink;
	struct vllogic_map map;
	struct uhsif_parser p;
	uint32_t words[120];	/* UHSIF_PAY_MIN */
	uint8_t block[16 + sizeof(words)];
	size_t len;
	int i, ok;

	memset(&sc, 0, sizeof(sc));
	memset(&p, 0, sizeof(p));
	sc.budget = 301;	/* 100 samples + one stray byte */
	sink.write = st_short_write;
	sink.flush = NULL;

	if (vllogic_map_build(logical, VLLOGIC_NUM_CHANNELS, &map) != 0) {
		fprintf(stderr, "  sink short: map build failed\n");
		return 1;
	}
	for (i = 0; i < 120; i++)
		words[i] = (uint32_t)i * 0x9E3779B9u;
	len = st_block(block, 0xFFFFFu, 0, words, 120, 0, 0);

	uhsif_parser_init(&p, &map, 0, 0, &sink, &sc);
	uhsif_parser_feed(&p, block, len);
	uhsif_parser_finish(&p);

	ok = p.st.sink_short > 0 &&
	     p.st.sink_short_bytes > 0 &&
	     sc.got == 301 &&
	     p.samples_out == (uint64_t)(sc.got / (size_t)map.unitsize);
	if (verbose || !ok)
		printf("  sink short: got=%zu samples_out=%llu short=%llu "
		       "short_bytes=%llu -> %s\n", sc.got,
		       (unsigned long long)p.samples_out,
		       (unsigned long long)p.st.sink_short,
		       (unsigned long long)p.st.sink_short_bytes,
		       ok ? "PASS" : "FAIL");

	return ok ? 0 : 1;
}

int uhsif_selftest(int verbose)
{
	static const struct st_case cases[] = {
		{ "unit=1 basic", { 0 }, 1, 0, 0, 0, 0, 0, 1 },
		{ "unit=2 basic", { 0, 8 }, 2, 0, 0, 0, 0, 0, 1 },
		{ "unit=3 basic", { 0, 8, 16 }, 3, 0, 0, 0, 0, 0, 1 },
		{ "unit=1 junk prefix", { 0 }, 1, 1, 0, 0, 0, 0, 1 },
		{ "unit=1 ack interleave", { 0 }, 1, 0, 1, 0, 0, 0, 1 },
		{ "unit=2 ack + junk", { 0, 8 }, 2, 1, 1, 0, 0, 0, 1 },
		{ "unit=1 crc resync", { 0 }, 1, 0, 0, 1, 0, 0, 1 },
		{ "unit=2 crc + ack", { 0, 8 }, 2, 1, 1, 1, 0, 0, 1 },
		{ "unit=1 limit 100", { 0 }, 1, 0, 0, 0, 100, 0, 1 },
		{ "unit=3 limit 33", { 0, 5, 19 }, 3, 1, 1, 0, 33, 0, 1 },
		{ "unit=3 all 20 ch", { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
					12, 13, 14, 15, 16, 17, 18, 19 }, 20,
		  0, 1, 0, 0, 0, 1 },
		{ "unit=2 channels 5,12", { 5, 12 }, 2, 0, 0, 0, 0, 0, 1 },
		/*
		 * Real-hardware geometry: 4092 words per block with 20
		 * channels is not a multiple of nchan, so snapshots straddle
		 * block boundaries on every block.
		 */
		{ "unit=3 20ch 4092/blk", { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
					11, 12, 13, 14, 15, 16, 17, 18, 19 }, 20,
		  0, 1, 0, 0, 4092, 1 },
		/* PC decimation, including a factor that does not divide 32. */
		{ "unit=3 20ch decimate 2", { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
					11, 12, 13, 14, 15, 16, 17, 18, 19 }, 20,
		  0, 1, 0, 0, 0, 2 },
		{ "unit=3 20ch decimate 8", { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
					11, 12, 13, 14, 15, 16, 17, 18, 19 }, 20,
		  0, 1, 0, 0, 0, 8 },
		{ "unit=1 decimate 20 lim 100", { 0 }, 1, 0, 0, 0, 100, 0, 20 },
	};
	size_t i;
	int ok = 1, ret;

	if (verbose)
		printf("[vllogic-selftest] protocol vectors\n");
	if (st_protocol(verbose) != 0)
		ok = 0;
	if (st_lut(verbose) != 0)
		ok = 0;
	if (st_header_bits(verbose) != 0)
		ok = 0;

	if (verbose)
		printf("[vllogic-selftest] UHSIF parser\n");
	if (st_crc_snap_reset(verbose) != 0)
		ok = 0;
	if (st_crc_overlap(verbose) != 0)
		ok = 0;
	if (verbose)
		printf("[vllogic-selftest] sink short accept\n");
	if (st_sink_short(verbose) != 0)
		ok = 0;
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		st_xs = 0x123456789ABCDEFull;
		ret = st_run_case(&cases[i], verbose);
		if (ret != 0)
			ok = 0;
	}

	if (verbose)
		printf("[vllogic-selftest] %s\n", ok ? "PASS" : "FAIL");

	return ok ? 0 : 1;
}
