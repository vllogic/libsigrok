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
 * USB transport for the VLLogic Logic20.
 *
 * Threading model (deliberately B2, no GSource for USB):
 *   - event thread: sole owner of libusb_handle_events_timeout(), runs the
 *     IN transfer callbacks (la_recv.c:949-1128),
 *   - parser thread: UHSIF state machine + de-interleave, hands expanded
 *     sample chunks to the session thread (la_recv.c:865-911),
 *   - session thread: pops chunks and calls sr_session_send().
 * Neither the event nor the parser thread calls any libsigrok API.
 */

#include <config.h>

#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <libusb.h>

#include "vllogic.h"

#define RX_RING_CAP		64	/* power of two, IN buffers in flight */
#define PTR_RING_CAP		64	/* power of two, IN buffers / rx ring */
/* chunk rings must hold every chunk: VLLOGIC_CHUNK_COUNT is 256 (2^8). */
#define CHUNK_RING_CAP		512	/* power of two, > VLLOGIC_CHUNK_COUNT */

struct vllogic_buf {
	uint8_t *data;
};

struct rx_item {
	struct vllogic_buf *buf;
	uint32_t len;
	int status;
};

struct vllogic_chunk {
	uint8_t *data;
	uint32_t len;
};

struct vllogic_urb {
	struct vllogic_rx *rx;
	struct libusb_transfer *xfer;
	struct vllogic_buf *cur;
	atomic_int active;
};

struct ptr_ring {
	void **slots;
	uint32_t mask;
	atomic_uint head;
	atomic_uint tail;
};

struct rx_ring {
	struct rx_item *slots;
	uint32_t mask;
	atomic_uint head;
	atomic_uint tail;
};

struct vllogic_rx {
	struct libusb_device_handle *hdl;
	struct libusb_context *usb_ctx;

	unsigned int urb_count;
	unsigned int urb_size;
	unsigned int buf_count;

	struct vllogic_buf *bufs;
	struct vllogic_urb *urbs;

	struct ptr_ring free_ring;	/* bufs, producer parser, consumer event */
	struct rx_ring rx_ring;		/* producer event, consumer parser */
	struct vllogic_buf *ev_spare;	/* owned by the event thread only */

	struct vllogic_chunk *chunks;
	struct ptr_ring chunk_free;	/* producer session, consumer parser */
	struct ptr_ring chunk_filled;	/* producer parser, consumer session */
	struct vllogic_chunk *cur_chunk;	/* session thread only */
	struct vllogic_chunk *parser_cur;	/* parser thread only */
	struct vllogic_chunk *parser_spare;	/* parser thread only */
	GQueue *spare_chunks;		/* overflow parking, never drop a pointer */

	pthread_t ev_thread;
	pthread_t parser_thread;
	int threads_started;

	atomic_int stopping;
	atomic_int ev_exit;
	atomic_int parser_exit;
	atomic_int ev_ready;
	atomic_int in_flight;
	atomic_int fatal;
	atomic_uint_fast64_t produced_bytes;	/* parser output, see limit */
	atomic_uint_fast64_t blocks_seen;	/* CRC-valid blocks parsed */
	atomic_int first_block_bad;
	atomic_int abandoned;		/* teardown timed out, do not free */
	unsigned int expected_div;
	uint32_t expected_mask;
	int first_checked;
	unsigned int last_drop_blocks;
	char first_msg[160];
	sem_t rx_sem;

	unsigned int chunks_pushed;	/* must equal VLLOGIC_CHUNK_COUNT */
	struct uhsif_parser parser;
	atomic_uint_fast64_t dropped_bytes;
	atomic_uint_fast64_t dropped_chunks;
	atomic_uint_fast64_t drop_flag_events;	/* set by parser, printed by session */
};

/* ------------------------------------------------------------------------- */
/* Lock free SPSC rings (la_recv.c:214-296)                                  */
/* ------------------------------------------------------------------------- */

static void ptr_ring_init(struct ptr_ring *r, void **slots, uint32_t cap)
{
	r->slots = slots;
	r->mask = cap - 1;
	atomic_init(&r->head, 0);
	atomic_init(&r->tail, 0);
}

static int ptr_push(struct ptr_ring *r, void *p)
{
	unsigned int h = atomic_load_explicit(&r->head, memory_order_relaxed);
	unsigned int t = atomic_load_explicit(&r->tail, memory_order_acquire);

	if (h - t >= r->mask + 1)
		return -1;
	r->slots[h & r->mask] = p;
	atomic_store_explicit(&r->head, h + 1, memory_order_release);

	return 0;
}

static void *ptr_pop(struct ptr_ring *r)
{
	unsigned int t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	unsigned int h = atomic_load_explicit(&r->head, memory_order_acquire);
	void *p;

	if (t == h)
		return NULL;
	p = r->slots[t & r->mask];
	atomic_store_explicit(&r->tail, t + 1, memory_order_release);

	return p;
}

static void rx_ring_init(struct rx_ring *r, struct rx_item *slots, uint32_t cap)
{
	r->slots = slots;
	r->mask = cap - 1;
	atomic_init(&r->head, 0);
	atomic_init(&r->tail, 0);
}

static int rx_push(struct rx_ring *r, struct vllogic_buf *buf, uint32_t len,
		int status)
{
	unsigned int h = atomic_load_explicit(&r->head, memory_order_relaxed);
	unsigned int t = atomic_load_explicit(&r->tail, memory_order_acquire);
	struct rx_item *it;

	if (h - t >= r->mask + 1)
		return -1;
	it = &r->slots[h & r->mask];
	it->buf = buf;
	it->len = len;
	it->status = status;
	atomic_store_explicit(&r->head, h + 1, memory_order_release);

	return 0;
}

static int rx_pop(struct rx_ring *r, struct rx_item *out)
{
	unsigned int t = atomic_load_explicit(&r->tail, memory_order_relaxed);
	unsigned int h = atomic_load_explicit(&r->head, memory_order_acquire);

	if (t == h)
		return -1;
	*out = r->slots[t & r->mask];
	atomic_store_explicit(&r->tail, t + 1, memory_order_release);

	return 0;
}

/* ------------------------------------------------------------------------- */
/* Sample chunk sink, called from the parser thread                          */
/* ------------------------------------------------------------------------- */

static size_t rx_sink_write(void *user, const uint8_t *data, size_t len);
static void rx_sink_flush(void *user);

/* Static, so the parser never points at a dead compound literal. */
static const struct uhsif_sink rx_sink = {
	.write = rx_sink_write,
	.flush = rx_sink_flush,
};

/* Publish the parser's current chunk; called on the parser thread only. */
static void rx_sink_flush(void *user)
{
	struct vllogic_rx *rx = user;
	struct vllogic_chunk *c = rx->parser_cur;

	if (!c)
		return;
	rx->parser_cur = NULL;
	if (c->len == 0)
		return;
	if (ptr_push(&rx->chunk_filled, c) == 0)
		return;
	/* Session is behind: count the loss, but never lose the pointer. */
	atomic_fetch_add_explicit(&rx->dropped_bytes, (uint64_t)c->len,
			memory_order_relaxed);
	atomic_fetch_add_explicit(&rx->dropped_chunks, 1, memory_order_relaxed);
	if (!rx->parser_spare) {
		rx->parser_spare = c;
		return;
	}
	/*
	 * The spare slot is already taken (and chunk_free may be empty while
	 * the session is behind).  Park it on an unbounded list so the chunk
	 * count stays conserved: free + filled + in-use + spare == COUNT.
	 */
	g_queue_push_tail(rx->spare_chunks, c);
}

static size_t rx_sink_write(void *user, const uint8_t *data, size_t len)
{
	struct vllogic_rx *rx = user;
	size_t done = 0;

	/*
	 * The first data block proves whether the device accepted DIV,
	 * channel mask and mode.  Validate it once, from the parser thread,
	 * before any sample reaches the session.
	 */
	if (!rx->first_checked) {
		struct uhsif_parser *p = &rx->parser;

		rx->first_checked = 1;
		if (p->hdr_div != rx->expected_div ||
		    (p->hdr_mask & 0xFFFFFu) != rx->expected_mask ||
		    p->hdr_mode != 0 || p->hdr_capturing != 1) {
			g_snprintf(rx->first_msg, sizeof(rx->first_msg),
				"First block header mismatch: div=%u (want %u), "
				"mask=0x%05X (want 0x%05X), mode=%u (want 0), "
				"capturing=%u (want 1).",
				p->hdr_div, rx->expected_div,
				p->hdr_mask & 0xFFFFFu, rx->expected_mask,
				p->hdr_mode, p->hdr_capturing);
			atomic_store_explicit(&rx->first_block_bad, 1,
					memory_order_release);
		}
	}

	/* Count even data that has to be dropped, so the sample limit is
	 * enforced on what the device produced, not only on what the session
	 * managed to consume. */
	atomic_fetch_add_explicit(&rx->produced_bytes, (uint64_t)len,
			memory_order_relaxed);

	/*
	 * The parser hands over one 32-sample snapshot at a time (96 B for
	 * 20 channels).  Coalesce them into full 64 KiB chunks: a chunk per
	 * snapshot makes the 64-entry filled ring hold only ~6 KiB, so the
	 * session thread cannot keep up and the ring overflows.
	 */
	while (done < len) {
		struct vllogic_chunk *c = rx->parser_cur;
		size_t unit = (size_t)rx->parser.map->unitsize;
		size_t n, room;

		if (!c) {
			c = ptr_pop(&rx->chunk_free);
			if (!c) {
				c = rx->parser_spare;
				rx->parser_spare = NULL;
			}
			if (!c)
				c = g_queue_pop_head(rx->spare_chunks);
			if (!c) {
				atomic_fetch_add_explicit(&rx->dropped_bytes, (uint64_t)(len - done), memory_order_relaxed);
				break;
			}
			c->len = 0;
			rx->parser_cur = c;
		}
		room = (size_t)VLLOGIC_CHUNK_SIZE - c->len;
		n = len - done;
		if (n > room)
			n = room;
		/*
		 * Every SR_DF_LOGIC packet must be a whole number of samples:
		 * a chunk cut in the middle of a unitsize would make
		 * length / unitsize round down and desynchronise the stream.
		 */
		n -= n % unit;
		if (n == 0) {
			if (len - done < unit) {
				/* Defensive: never call us with a partial sample. */
				atomic_fetch_add_explicit(&rx->dropped_bytes, (uint64_t)(len - done), memory_order_relaxed);
				break;
			}
			/* Less than one sample fits: publish and start a new one. */
			rx_sink_flush(rx);
			continue;
		}
		memcpy(c->data + c->len, data + done, n);
		c->len += (uint32_t)n;
		done += n;
		if (VLLOGIC_CHUNK_SIZE - c->len < unit)
			rx_sink_flush(rx);
	}

	return done;
}

/* ------------------------------------------------------------------------- */
/* libusb IN callbacks and event thread                                      */
/* ------------------------------------------------------------------------- */

static int urb_submit(struct vllogic_rx *rx, struct vllogic_urb *u)
{
	int ret = libusb_submit_transfer(u->xfer);

	if (ret == 0) {
		atomic_store_explicit(&u->active, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&rx->in_flight, 1,
				memory_order_relaxed);
	}

	return ret;
}

static void LIBUSB_CALL in_cb(struct libusb_transfer *t)
{
	struct vllogic_urb *u = t->user_data;
	struct vllogic_rx *rx = u->rx;
	int status = t->status;
	int len = t->actual_length;

	atomic_store_explicit(&u->active, 0, memory_order_relaxed);
	atomic_fetch_sub_explicit(&rx->in_flight, 1, memory_order_relaxed);

	if (status == LIBUSB_TRANSFER_CANCELLED) {
		/* Fall through to the tail handoff below. */
	} else if (status == LIBUSB_TRANSFER_NO_DEVICE) {
		atomic_store_explicit(&rx->fatal, 1, memory_order_relaxed);
	} else if (status != LIBUSB_TRANSFER_COMPLETED &&
		   status != LIBUSB_TRANSFER_TIMED_OUT) {
		atomic_store_explicit(&rx->fatal, 1, memory_order_relaxed);
	}

	if (!atomic_load_explicit(&rx->stopping, memory_order_relaxed) &&
	    status != LIBUSB_TRANSFER_NO_DEVICE) {
		struct vllogic_buf *nb;

		/* Zero length completion: keep the buffer, resubmit. */
		if (len == 0) {
			if (urb_submit(rx, u) != 0) {
				atomic_store_explicit(&rx->fatal, 1,
						memory_order_relaxed);
				u->cur = NULL;
			}
			return;
		}

		nb = ptr_pop(&rx->free_ring);
		if (!nb) {
			/* Reclaim a buffer retired earlier by this thread. */
			nb = rx->ev_spare;
			rx->ev_spare = NULL;
		}
		if (!nb) {
			/* Parser is behind: drop the chunk, keep the buffer. */
			atomic_fetch_add_explicit(&rx->dropped_bytes, (uint64_t)len, memory_order_relaxed);
			if (urb_submit(rx, u) != 0) {
				atomic_store_explicit(&rx->fatal, 1,
						memory_order_relaxed);
				u->cur = NULL;
			}
			return;
		}

		/* Swap in the new buffer before resubmitting. */
		{
			struct vllogic_buf *old = u->cur;

			u->cur = nb;
			t->buffer = nb->data;
			t->length = (int)rx->urb_size;

			{
				int ret = -1;
				int attempt;

				for (attempt = 0; attempt < 3; attempt++) {
					ret = urb_submit(rx, u);
					if (ret == 0)
						break;
					g_usleep(1000);
				}
				if (ret != 0) {
					atomic_store_explicit(&rx->fatal, 1,
							memory_order_relaxed);
					u->cur = NULL;
					return;
				}
			}

			/* Publish the old buffer to the parser.  On overflow the
			 * buffer is retired: the free ring is single-producer
			 * (parser only), so this thread parks it instead. */
			if (rx_push(&rx->rx_ring, old, (uint32_t)len, status) != 0) {
				atomic_fetch_add_explicit(&rx->dropped_bytes, (uint64_t)len, memory_order_relaxed);
				if (!rx->ev_spare)
					rx->ev_spare = old;
			} else {
				sem_post(&rx->rx_sem);
			}
		}
		return;
	}

	/*
	 * Stopping / cancelled: a cancelled bulk URB still reports the bytes
	 * that were already received, and that tail belongs to the capture
	 * window, so it must be handed to the parser instead of being dropped.
	 */
	if (len > 0 && u->cur && status != LIBUSB_TRANSFER_NO_DEVICE) {
		if (rx_push(&rx->rx_ring, u->cur, (uint32_t)len, status) == 0) {
			sem_post(&rx->rx_sem);
		} else {
			atomic_fetch_add_explicit(&rx->dropped_bytes, (uint64_t)len, memory_order_relaxed);
			if (!rx->ev_spare)
				rx->ev_spare = u->cur;
		}
	}
	u->cur = NULL;
}

static void *event_thread(void *arg)
{
	struct vllogic_rx *rx = arg;
	int ok = 1;
	unsigned int i;

	for (i = 0; i < rx->urb_count; i++) {
		struct vllogic_urb *u = &rx->urbs[i];

		u->rx = rx;
		u->cur = ptr_pop(&rx->free_ring);
		if (!u->cur) {
			ok = 0;
			break;
		}
		libusb_fill_bulk_transfer(u->xfer, rx->hdl, VLLOGIC_EP_IN,
				u->cur->data, (int)rx->urb_size, in_cb, u, 0);
		if (urb_submit(rx, u) != 0) {
			u->cur = NULL;
			ok = 0;
			break;
		}
	}

	atomic_store_explicit(&rx->ev_ready, ok ? 1 : -1,
			memory_order_release);

	while (!atomic_load_explicit(&rx->ev_exit, memory_order_acquire)) {
		struct timeval tv;

		tv.tv_sec = 0;
		tv.tv_usec = 10 * 1000;
		libusb_handle_events_timeout(rx->usb_ctx, &tv);
	}

	return NULL;
}

/* ------------------------------------------------------------------------- */
/* Parser thread                                                             */
/* ------------------------------------------------------------------------- */

static void *parser_thread(void *arg)
{
	struct vllogic_rx *rx = arg;
	struct rx_item it;

	for (;;) {
		if (rx_pop(&rx->rx_ring, &it) == 0) {
			if (it.len > 0 &&
			    it.status != LIBUSB_TRANSFER_NO_DEVICE)
				uhsif_parser_feed(&rx->parser, it.buf->data,
						it.len);
			atomic_store_explicit(&rx->blocks_seen,
					rx->parser.st.blocks,
					memory_order_relaxed);
			if (rx->parser.st.drop_blocks !=
			    rx->last_drop_blocks) {
				rx->last_drop_blocks =
					rx->parser.st.drop_blocks;
				/* Logging is the session thread's job. */
				atomic_fetch_add_explicit(
					&rx->drop_flag_events, 1,
					memory_order_relaxed);
			}
			(void)ptr_push(&rx->free_ring, it.buf);
			continue;
		}
		if (atomic_load_explicit(&rx->parser_exit, memory_order_acquire))
			break;

		{
			struct timespec ts;

			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_nsec += 20 * 1000 * 1000;
			if (ts.tv_nsec >= 1000000000L) {
				ts.tv_sec++;
				ts.tv_nsec -= 1000000000L;
			}
			sem_timedwait(&rx->rx_sem, &ts);
		}
	}

	uhsif_parser_finish(&rx->parser);

	return NULL;
}

/* ------------------------------------------------------------------------- */
/* Life cycle                                                                */
/* ------------------------------------------------------------------------- */

struct vllogic_rx *vllogic_rx_new(const struct sr_dev_inst *sdi,
		const struct vllogic_map *map, uint64_t limit_samples)
{
	struct dev_context *devc = sdi->priv;
	struct sr_usb_dev_inst *usb = sdi->conn;
	struct vllogic_rx *rx;
	unsigned int i;

	if (!devc || !usb || !usb->devhdl)
		return NULL;

	rx = g_malloc0(sizeof(*rx));
	rx->hdl = usb->devhdl;
	rx->usb_ctx = devc->usb_ctx;
	rx->urb_count = VLLOGIC_URB_COUNT;
	rx->urb_size = VLLOGIC_URB_SIZE;
	rx->buf_count = VLLOGIC_BUF_COUNT;

	atomic_init(&rx->stopping, 0);
	atomic_init(&rx->ev_exit, 0);
	atomic_init(&rx->parser_exit, 0);
	atomic_init(&rx->ev_ready, 0);
	atomic_init(&rx->in_flight, 0);
	atomic_init(&rx->fatal, 0);
	atomic_init(&rx->produced_bytes, 0);
	atomic_init(&rx->blocks_seen, 0);
	atomic_init(&rx->first_block_bad, 0);
	atomic_init(&rx->abandoned, 0);
	atomic_init(&rx->dropped_bytes, 0);
	rx->expected_div = devc->div;
	rx->expected_mask = map->mask;
	sem_init(&rx->rx_sem, 0, 0);

	rx->bufs = g_malloc0(rx->buf_count * sizeof(*rx->bufs));
	for (i = 0; i < rx->buf_count; i++)
		rx->bufs[i].data = g_malloc(rx->urb_size);

	rx->urbs = g_malloc0(rx->urb_count * sizeof(*rx->urbs));
	for (i = 0; i < rx->urb_count; i++) {
		rx->urbs[i].xfer = libusb_alloc_transfer(0);
		atomic_init(&rx->urbs[i].active, 0);
	}

	{
		void **free_slots = g_malloc0(PTR_RING_CAP * sizeof(void *));
		void **chunk_free_slots = g_malloc0(CHUNK_RING_CAP * sizeof(void *));
		void **chunk_filled_slots = g_malloc0(CHUNK_RING_CAP * sizeof(void *));
		struct rx_item *rx_slots = g_malloc0(RX_RING_CAP *
				sizeof(struct rx_item));

		ptr_ring_init(&rx->free_ring, free_slots, PTR_RING_CAP);
		ptr_ring_init(&rx->chunk_free, chunk_free_slots, CHUNK_RING_CAP);
		ptr_ring_init(&rx->chunk_filled, chunk_filled_slots,
				CHUNK_RING_CAP);
		rx_ring_init(&rx->rx_ring, rx_slots, RX_RING_CAP);
	}

	for (i = 0; i < rx->buf_count; i++)
		(void)ptr_push(&rx->free_ring, &rx->bufs[i]);

	rx->chunks = g_malloc0(VLLOGIC_CHUNK_COUNT * sizeof(*rx->chunks));
	rx->chunks_pushed = 0;
	for (i = 0; i < VLLOGIC_CHUNK_COUNT; i++) {
		rx->chunks[i].data = g_malloc(VLLOGIC_CHUNK_SIZE);
		rx->chunks[i].len = 0;
		if (ptr_push(&rx->chunk_free, &rx->chunks[i]) == 0)
			rx->chunks_pushed++;
	}

	rx->spare_chunks = g_queue_new();

	/*
	 * Pool invariant: every allocated chunk must be reachable from the
	 * free ring (or be in flight).  With CHUNK_RING_CAP > COUNT a failed
	 * push can only mean a programming error, so surface it loudly.
	 */
	if (rx->chunks_pushed != VLLOGIC_CHUNK_COUNT)
		sr_err("chunk pool: only %u of %d chunks entered the free "
			"ring; the ring is too small.", rx->chunks_pushed,
			VLLOGIC_CHUNK_COUNT);
	else
		sr_info("chunk pool: %u x %u KiB chunks in the free ring.",
			rx->chunks_pushed,
			VLLOGIC_CHUNK_SIZE / 1024);

	uhsif_parser_init(&rx->parser, map, limit_samples, devc->decimate,
			&rx_sink, rx);
	return rx;
}

void vllogic_rx_free(struct vllogic_rx *rx)
{
	unsigned int i;

	if (!rx)
		return;

	vllogic_rx_stop(rx);

	/*
	 * A timed-out teardown may still have URB callbacks referencing the
	 * transfers, buffers and this structure.  Leaking them is the only
	 * safe option; freeing here would turn a stuck capture into a UAF.
	 */
	if (atomic_load_explicit(&rx->abandoned, memory_order_acquire)) {
		sr_err("Leaking USB receive state: IN transfers still active.");
		return;
	}

	for (i = 0; i < rx->urb_count; i++) {
		if (rx->urbs[i].xfer)
			libusb_free_transfer(rx->urbs[i].xfer);
	}
	for (i = 0; i < rx->buf_count; i++)
		g_free(rx->bufs[i].data);
	for (i = 0; i < VLLOGIC_CHUNK_COUNT; i++)
		g_free(rx->chunks[i].data);

	if (rx->spare_chunks) {
		g_queue_free(rx->spare_chunks);
		rx->spare_chunks = NULL;
	}
	g_free(rx->chunks);
	g_free(rx->bufs);
	g_free(rx->urbs);
	g_free(rx->free_ring.slots);
	g_free(rx->chunk_free.slots);
	g_free(rx->chunk_filled.slots);
	g_free(rx->rx_ring.slots);
	sem_destroy(&rx->rx_sem);
	g_free(rx);
}

int vllogic_rx_start(struct vllogic_rx *rx)
{
	int waited;

	atomic_store_explicit(&rx->stopping, 0, memory_order_relaxed);
	atomic_store_explicit(&rx->ev_exit, 0, memory_order_relaxed);
	atomic_store_explicit(&rx->parser_exit, 0, memory_order_relaxed);
	atomic_store_explicit(&rx->ev_ready, 0, memory_order_relaxed);

	if (pthread_create(&rx->ev_thread, NULL, event_thread, rx) != 0) {
		sr_err("Failed to start USB event thread.");
		return SR_ERR;
	}
	if (pthread_create(&rx->parser_thread, NULL, parser_thread, rx) != 0) {
		sr_err("Failed to start UHSIF parser thread.");
		/*
		 * The event thread has already submitted up to 16 IN URBs.
		 * Cancel and drain them before joining, otherwise rx_free()
		 * would free transfers that libusb still owns.
		 */
		/* Let the event thread finish submitting the initial URBs. */
		for (waited = 0; waited < 1000; waited++) {
			if (atomic_load_explicit(&rx->ev_ready,
						 memory_order_acquire) != 0)
				break;
			g_usleep(1000);
		}
		atomic_store_explicit(&rx->stopping, 1, memory_order_relaxed);
		for (waited = 0; waited < 2000; waited += 10) {
			unsigned int i;

			if (atomic_load_explicit(&rx->in_flight,
						 memory_order_acquire) == 0)
				break;
			for (i = 0; i < rx->urb_count; i++) {
				if (atomic_load_explicit(&rx->urbs[i].active,
							 memory_order_relaxed))
					libusb_cancel_transfer(
						rx->urbs[i].xfer);
			}
			{
				struct timeval tv;

				tv.tv_sec = 0;
				tv.tv_usec = 10 * 1000;
				libusb_handle_events_timeout(rx->usb_ctx, &tv);
			}
		}
		if (atomic_load_explicit(&rx->in_flight,
					 memory_order_acquire) != 0) {
			sr_err("IN transfers still active after parser thread "
				"failure; marking the pipeline abandoned.");
			atomic_store_explicit(&rx->abandoned, 1,
					memory_order_relaxed);
		}
		atomic_store_explicit(&rx->ev_exit, 1, memory_order_relaxed);
		pthread_join(rx->ev_thread, NULL);
		if (atomic_load_explicit(&rx->in_flight,
					 memory_order_acquire) != 0) {
			sr_err("IN transfers survived parser thread failure; "
				"marking the pipeline abandoned.");
			atomic_store_explicit(&rx->abandoned, 1,
					memory_order_relaxed);
		}
		return SR_ERR;
	}
	rx->threads_started = 1;

	for (waited = 0; waited < 1000; waited++) {
		if (atomic_load_explicit(&rx->ev_ready,
					 memory_order_acquire) != 0)
			break;
		g_usleep(1000);
	}
	if (atomic_load_explicit(&rx->ev_ready, memory_order_acquire) != 1) {
		sr_err("Failed to submit the initial IN transfers.");
		vllogic_rx_stop(rx);
		return SR_ERR;
	}

	return SR_OK;
}

void vllogic_rx_set_stopping(struct vllogic_rx *rx)
{
	if (rx)
		atomic_store_explicit(&rx->stopping, 1, memory_order_relaxed);
}

void vllogic_rx_stop(struct vllogic_rx *rx)
{
	unsigned int i;
	int waited;

	if (!rx || !rx->threads_started)
		return;

	atomic_store_explicit(&rx->stopping, 1, memory_order_relaxed);

	/*
	 * Cancellation is asynchronous.  Keep cancelling and advancing the
	 * libusb event loop until every completion callback ran (in_flight
	 * reaches 0), up to 5 s.  Freeing a still-active transfer after that
	 * would be a use-after-free, so the pipeline is marked abandoned and
	 * rx_free() leaks it instead.
	 */
	/*
	 * Only the event thread may call libusb_handle_events_timeout():
	 * driving the loop here as well would let in_cb() run on two
	 * threads at once.  Cancel everything once, then let the event
	 * thread reap the completions (its loop runs every 10 ms).
	 */
	for (i = 0; i < rx->urb_count; i++) {
		if (atomic_load_explicit(&rx->urbs[i].active,
					 memory_order_relaxed))
			libusb_cancel_transfer(rx->urbs[i].xfer);
	}
	for (waited = 0; waited < 5000; waited += 5) {
		if (atomic_load_explicit(&rx->in_flight,
					 memory_order_acquire) == 0)
			break;
		g_usleep(5 * 1000);
	}
	if (atomic_load_explicit(&rx->in_flight, memory_order_acquire) != 0) {
		sr_err("IN transfers still in flight after 5 s; marking the "
			"receive pipeline abandoned (memory will be leaked).");
		atomic_store_explicit(&rx->abandoned, 1, memory_order_relaxed);
	}

	atomic_store_explicit(&rx->ev_exit, 1, memory_order_relaxed);
	pthread_join(rx->ev_thread, NULL);
	if (atomic_load_explicit(&rx->in_flight, memory_order_acquire) != 0) {
		sr_err("IN transfers still active after joining the event "
			"thread; marking the pipeline abandoned.");
		atomic_store_explicit(&rx->abandoned, 1, memory_order_relaxed);
	}

	/* No more producers: let the parser drain the ring and exit. */
	atomic_store_explicit(&rx->parser_exit, 1, memory_order_relaxed);
	sem_post(&rx->rx_sem);
	pthread_join(rx->parser_thread, NULL);

	rx->threads_started = 0;
}

size_t vllogic_rx_pop(struct vllogic_rx *rx, const uint8_t **data)
{
	struct vllogic_chunk *c;

	if (!rx || rx->cur_chunk)
		return 0;
	c = ptr_pop(&rx->chunk_filled);
	if (!c)
		return 0;
	rx->cur_chunk = c;
	*data = c->data;

	return c->len;
}

void vllogic_rx_release(struct vllogic_rx *rx)
{
	if (!rx || !rx->cur_chunk)
		return;
	(void)ptr_push(&rx->chunk_free, rx->cur_chunk);
	rx->cur_chunk = NULL;
}

void vllogic_rx_get_stats(struct vllogic_rx *rx, struct uhsif_stats *stats,
		uint64_t *dropped_chunks)
{
	if (stats) {
		if (rx)
			*stats = rx->parser.st;
		else
			memset(stats, 0, sizeof(*stats));
	}
	if (dropped_chunks) {
		*dropped_chunks = rx ? atomic_load_explicit(&rx->dropped_bytes,
			memory_order_relaxed) : 0;
	}
}

uint64_t vllogic_rx_drop_events(const struct vllogic_rx *rx)
{
	return rx ? atomic_load_explicit(&rx->drop_flag_events,
			memory_order_relaxed) : 0;
}

/** Samples emitted by the parser so far (including any dropped chunks). */
uint64_t vllogic_rx_samples_produced(const struct vllogic_rx *rx)
{
	uint64_t bytes;

	if (!rx || !rx->parser.map || rx->parser.map->unitsize <= 0)
		return 0;
	bytes = atomic_load_explicit(&rx->produced_bytes, memory_order_relaxed);

	return bytes / (uint64_t)rx->parser.map->unitsize;
}

/** CRC-valid blocks parsed so far (for the start-up watchdog). */
uint64_t vllogic_rx_blocks(const struct vllogic_rx *rx)
{
	if (!rx)
		return 0;

	return atomic_load_explicit(&rx->blocks_seen, memory_order_relaxed);
}

/**
 * Report a first-block header mismatch.
 *
 * @return 1 and fill @a buf when the first data block disagreed with the
 *         requested div/mask/mode, 0 otherwise.
 */
int vllogic_rx_first_block_bad(const struct vllogic_rx *rx, char *buf,
		size_t buflen)
{
	if (!rx || !atomic_load_explicit(&rx->first_block_bad,
					 memory_order_acquire))
		return 0;
	if (buf && buflen > 0)
		g_strlcpy(buf, rx->first_msg, buflen);

	return 1;
}

/** Report a fatal transfer error (device gone, resubmit failed, ...). */
int vllogic_rx_fatal(struct vllogic_rx *rx)
{
	if (!rx)
		return 1;

	return atomic_load_explicit(&rx->fatal, memory_order_acquire);
}

/* ------------------------------------------------------------------------- */
/* Command channel                                                           */
/* ------------------------------------------------------------------------- */

static uint32_t rd32le(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Source: la_recv.c:1130-1148 (scan_ack_block). */
static int scan_ack_block(const uint8_t *buf, int len)
{
	int i;

	for (i = 0; i + UHSIF_HDR_SIZE <= len; i++) {
		uint32_t w0, w1, w2, w3;

		if ((rd32le(buf + i) & 0xFFFFu) != UHSIF_BLK_MAGIC16)
			continue;
		w0 = rd32le(buf + i + 0);
		w1 = rd32le(buf + i + 4);
		w2 = rd32le(buf + i + 8);
		w3 = rd32le(buf + i + 12);
		if ((w0 >> 16) != vllogic_crc16(w1, w2, w3))
			continue;
		if (((w3 >> 12) & 0xFFFu) != 0)
			continue;
		return 1;
	}

	return 0;
}

/* Source: la_recv.c:1150-1161 (sync_drain). */
static void sync_drain(struct vllogic_rx *rx, int reads, int timeout_ms)
{
	uint8_t buf[4096];
	int i;

	for (i = 0; i < reads; i++) {
		int transferred = 0;
		int ret;

		ret = libusb_bulk_transfer(rx->hdl, VLLOGIC_EP_IN, buf,
				(int)sizeof(buf), &transferred, timeout_ms);
		if (ret < 0 || transferred <= 0)
			break;
	}
}

/* Source: la_recv.c:1163-1196 (sync_wait_ack). */
static int sync_wait_ack(struct vllogic_rx *rx)
{
	uint8_t buf[4096];
	uint8_t carry[16];
	int carry_len = 0;
	int i;

	for (i = 0; i < VLLOGIC_ACK_READS; i++) {
		int transferred = 0;
		int ret;

		ret = libusb_bulk_transfer(rx->hdl, VLLOGIC_EP_IN, buf,
				(int)sizeof(buf), &transferred,
				VLLOGIC_ACK_TIMEOUT_MS);
		if (ret < 0 && ret != LIBUSB_ERROR_TIMEOUT)
			return 0;
		if (transferred <= 0)
			continue;
		if (carry_len > 0) {
			uint8_t tmp[16 + 4096];
			size_t jl = (size_t)carry_len + (size_t)transferred;

			memcpy(tmp, carry, (size_t)carry_len);
			memcpy(tmp + carry_len, buf, (size_t)transferred);
			if (scan_ack_block(tmp, carry_len + transferred))
				return 1;
			/*
			 * Keep the tail of the *joined* stream: a short read
			 * must not truncate a header that started in the
			 * previous buffer.
			 */
			if (jl >= 15) {
				memcpy(carry, tmp + jl - 15, 15);
				carry_len = 15;
			} else {
				memcpy(carry, tmp, jl);
				carry_len = (unsigned int)jl;
			}
			continue;
		}
		if (scan_ack_block(buf, transferred))
			return 1;
		if (transferred >= 15) {
			memcpy(carry, buf + transferred - 15, 15);
			carry_len = 15;
		} else {
			memcpy(carry, buf, (size_t)transferred);
			carry_len = transferred;
		}
	}

	return 0;
}

static int cmd_write(struct vllogic_rx *rx, uint32_t cmd, uint32_t param)
{
	uint8_t pkt[UHSIF_CMD_SIZE];
	int transferred = 0;
	int ret;

	vllogic_cmd_build(pkt, cmd, param);
	ret = libusb_bulk_transfer(rx->hdl, VLLOGIC_EP_OUT, pkt,
			(int)sizeof(pkt), &transferred, 1000);
	if (ret != 0) {
		sr_err("Command 0x%02X failed: %s.", cmd, libusb_error_name(ret));
		return SR_ERR;
	}
	if (transferred != UHSIF_CMD_SIZE) {
		sr_err("Command 0x%02X: short write (%d).", cmd, transferred);
		return SR_ERR;
	}

	return SR_OK;
}

/* Source: la_recv.c:1198-1218 (sync_send_cmd). */
static int sync_send_cmd(struct vllogic_rx *rx, uint32_t cmd, uint32_t param)
{
	int attempt;

	for (attempt = 0; attempt < VLLOGIC_CMD_RETRIES; attempt++) {
		if (cmd_write(rx, cmd, param) != SR_OK)
			continue;
		if (sync_wait_ack(rx))
			return SR_OK;
	}

	/*
	 * No ACK is not necessarily fatal: an ACK only proves that a CRC
	 * valid frame arrived, not that the command was executed.
	 */
	sr_warn("Command 0x%02X was not acknowledged.", cmd);

	return SR_ERR;
}

/**
 * Run the mandatory start-up sequence:
 *   STOP, FLUSH, MASK, LUT x 5, DIV, PWM0, PWM1, MODE_NORMAL
 * followed by the >= 25 ms PWM settling time.  The IN URBs are submitted and
 * START is sent afterwards by the caller, see la_recv.c:1220-1251.
 */
/**
 * Measure the usable IN bandwidth with a self-contained counter-mode burst.
 *
 * Must be called before vllogic_rx_start(): the event thread is not running
 * yet, so this owns EP1 exclusively (a second reader would race in_cb()).
 * The capture path must not see counter-mode blocks, so the probe only uses
 * the synchronous bulk path and always restores MODE_NORMAL and drains.
 *
 * @param window_ms  sampling window, default 200 ms (see api.c)
 * @param bps        measured bytes/second (not MB/s)
 * @return SR_OK on success, SR_ERR if any command or the read loop failed
 */
int vllogic_probe_link(struct vllogic_rx *rx, unsigned int window_ms,
		uint64_t *bps)
{
	uint8_t *buf;
	struct timespec t0, t1;
	uint64_t bytes = 0;
	int64_t deadline_us;
	int ret = SR_ERR;
	gboolean started = FALSE;

	if (!rx || !bps || window_ms == 0)
		return SR_ERR;

	buf = g_malloc(256 * 1024);	/* Windows synchronous read cap */

	sync_drain(rx, 32, 5);
	if (sync_send_cmd(rx, UHSIF_CMD_STOP, 0) != SR_OK)
		goto out;
	if (sync_send_cmd(rx, UHSIF_CMD_FLUSH, 0) != SR_OK)
		goto out;
	if (sync_send_cmd(rx, UHSIF_CMD_MAX_PAYLOAD,
			  UHSIF_DEFAULT_PAYLOAD) != SR_OK)
		goto out;
	if (sync_send_cmd(rx, UHSIF_CMD_CHANNEL_MASK, 0x3) != SR_OK)
		goto out;
	if (sync_send_cmd(rx, UHSIF_CMD_ISERDES_DIV, 2) != SR_OK)
		goto out;
	if (sync_send_cmd(rx, UHSIF_CMD_MODE_COUNTER, 0) != SR_OK)
		goto out;

	if (cmd_write(rx, UHSIF_CMD_START, 0) != SR_OK)
		goto out;
	started = TRUE;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	deadline_us = (int64_t)window_ms * 1000;

	for (;;) {
		int transferred = 0;
		int r;
		int64_t elapsed_us;

		clock_gettime(CLOCK_MONOTONIC, &t1);
		elapsed_us = (int64_t)(t1.tv_sec - t0.tv_sec) * 1000000 +
				(t1.tv_nsec - t0.tv_nsec) / 1000;
		if (elapsed_us >= deadline_us)
			break;

		r = libusb_bulk_transfer(rx->hdl, VLLOGIC_EP_IN, buf,
				256 * 1024, &transferred, 50);
		if (r == LIBUSB_ERROR_TIMEOUT)
			continue;
		if (r < 0)
			break;
		if (transferred > 0)
			bytes += (uint64_t)transferred;
	}

	clock_gettime(CLOCK_MONOTONIC, &t1);
	{
		int64_t elapsed_us = (int64_t)(t1.tv_sec - t0.tv_sec) * 1000000 +
				(t1.tv_nsec - t0.tv_nsec) / 1000;

		if (bytes > 0 && elapsed_us > 0) {
			*bps = bytes * 1000000ull / (uint64_t)elapsed_us;
			ret = SR_OK;
		}
	}

out:
	if (started) {
		(void)sync_send_cmd(rx, UHSIF_CMD_STOP, 0);
		(void)sync_send_cmd(rx, UHSIF_CMD_MODE_NORMAL, 0);
	}
	sync_drain(rx, 32, 5);
	g_free(buf);

	return ret;
}

int vllogic_config_device(struct vllogic_rx *rx, const struct dev_context *devc)
{
	uint32_t lut[5];
	int i;
	int ret = SR_OK;

	sync_drain(rx, 32, 5);

	if (sync_send_cmd(rx, UHSIF_CMD_STOP, 0) != SR_OK)
		return SR_ERR;
	if (sync_send_cmd(rx, UHSIF_CMD_FLUSH, 0) != SR_OK)
		return SR_ERR;
	if (sync_send_cmd(rx, UHSIF_CMD_CHANNEL_MASK, devc->map.mask) != SR_OK)
		return SR_ERR;

	vllogic_lut_build(devc->map.mask, lut);
	for (i = 0; i < 5; i++) {
		if (sync_send_cmd(rx, UHSIF_CMD_LUT0 + (uint32_t)i,
				  lut[i]) != SR_OK)
			return SR_ERR;
	}

	if (sync_send_cmd(rx, UHSIF_CMD_ISERDES_DIV, devc->div) != SR_OK)
		return SR_ERR;
	if (sync_send_cmd(rx, UHSIF_CMD_VBIAS_PWM0, devc->pwm0) != SR_OK)
		return SR_ERR;
	if (sync_send_cmd(rx, UHSIF_CMD_VBIAS_PWM1, devc->pwm1) != SR_OK)
		return SR_ERR;
	if (sync_send_cmd(rx, UHSIF_CMD_MODE_NORMAL, 0) != SR_OK)
		return SR_ERR;

	/* PWM settling time, the specification requires >= 25 ms. */
	g_usleep(30 * 1000);

	return ret;
}

/**
 * Send a command frame without waiting for its ACK.  Used for START/STOP
 * while the IN URBs are already armed (the ACK would be consumed by the
 * capture path, and its reception does not prove execution anyway).
 */
int vllogic_send_simple(struct vllogic_rx *rx, uint32_t cmd, uint32_t param)
{
	if (!rx)
		return SR_ERR;

	return cmd_write(rx, cmd, param);
}
