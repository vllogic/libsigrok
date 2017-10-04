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

#include <config.h>
#include <string.h>
#include "protocol.h"

#define VLLOGIC_REQUESET_REG_RW				0x00

static int read_registers(struct sr_usb_dev_inst *usb, uint16_t addr, uint16_t len, uint32_t *data)
{
	int ret;
	ret = libusb_control_transfer(usb->devhdl, LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_ENDPOINT_IN | LIBUSB_RECIPIENT_INTERFACE,
		VLLOGIC_REQUESET_REG_RW, addr, VLLOGIC_INTERFACE, (uint8_t *)data, len, USB_TIMEOUT_MS);
	if (ret != len)
		return SR_ERR;
	else
		return SR_OK;
}

static int write_registers(struct sr_usb_dev_inst *usb, uint16_t addr, uint16_t len, uint32_t *data)
{
	int ret;
	ret = libusb_control_transfer(usb->devhdl, LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_ENDPOINT_OUT | LIBUSB_RECIPIENT_INTERFACE,
		VLLOGIC_REQUESET_REG_RW, addr, VLLOGIC_INTERFACE, (uint8_t *)data, len, USB_TIMEOUT_MS);

	if (ret != len)
		return SR_ERR;
	else
		return SR_OK;
}

static int version_check(uint32_t version)
{
	switch (version & 0xff000000)
	{
	case VLLOGIC_VERSION_SCHEME_LPC43XX:
		sr_spew("Find VLLOGIC_VERSION_SCHEME_LPC43XX.");
		switch (version & 0x00ff0000)
		{
		case VLLOGIC_BOARD_VL1602ED:
			sr_spew("Find VLLOGIC_BOARD_VL1602ED.");
			break;
		case VLLOGIC_BOARD_VL1602:
			sr_spew("Find VLLOGIC_BOARD_VL1602.");
			break;
		default:
			sr_spew("Cannot Match Board");
			return -1;
		}
		break;
	default:
		sr_spew("Cannot Match Scheme");
		return -1;
	}
	return 0;
}

SR_PRIV struct dev_context *vll_new_device(struct drv_context *drvc, struct sr_usb_dev_inst *usb)
{
	int i, ret;
	uint32_t version;
	struct dev_context *devc;

	(void)drvc;

	sr_spew("vll_new_device version check.");
	// device version check
	ret = read_registers(usb, 0, 4, &version);
	if (ret != SR_OK)
		return NULL;

	ret = version_check(version);
	if (ret < 0)
		return NULL;

	sr_spew("vll_new_device create new device.");
	// create new device
	devc = g_malloc0(sizeof(struct dev_context));
	memset(devc, 0, sizeof(struct dev_context));

	switch (version & 0xff000000)
	{
	case VLLOGIC_VERSION_SCHEME_LPC43XX:
		memcpy(devc->vendor, "Vllogic", sizeof("Vllogic"));
		switch (version & 0x00ff0000)
		{
		case VLLOGIC_BOARD_VL1602ED:
			memcpy(devc->model, "VL1602ED", sizeof("VL1602ED"));
			break;
		case VLLOGIC_BOARD_VL1602:
			memcpy(devc->model, "VL1602", sizeof("VL1602"));
			break;
		}
		break;
	}

	sr_spew("vll_new_device read regs.");
	ret = read_registers(usb, 0, sizeof(struct lpc43xx_registers_list_t) - sizeof(struct vllogic_in_pkt_info_t),
		(uint32_t *)&devc->lpc43xx_registers);
	if (ret != SR_OK) {
		g_free(devc);
		return NULL;
	}

	for (i = 0; i < 16; i++)
	{
		if (devc->lpc43xx_registers.board_in_channels_mask & (0x1ul << i))
		{
			devc->digital_channel_num++;
		}
	}
	sr_spew("vll_new_device get digital channel: %d", devc->digital_channel_num);

	for (i = 16; i < 32; i++)
	{
		if (devc->lpc43xx_registers.board_in_channels_mask & (0x1ul << i))
		{
			devc->analog_channel_num++;
		}
	}
	sr_spew("vll_new_device get analog channel: %d", devc->analog_channel_num);

	return devc;
}

static void abort_acquisition(struct dev_context *devc)
{
	if (devc->acq_aborted == FALSE) {
		int i;
		
		devc->acq_aborted = TRUE;

		for (i = BULK_IN_TRANSFERS_NUM - 1; i >= 0; i--) {
			if (devc->transfers[i])
				libusb_cancel_transfer(devc->transfers[i]);
		}
	}
}

static void finish_acquisition(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

	std_session_send_df_end(sdi);

	usb_source_remove(sdi->session, devc->ctx);

	g_free(devc->transferbuffer);
	g_free(devc->convbuffer);
}

static void free_transfer(struct libusb_transfer *transfer)
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	int i;

	sdi = transfer->user_data;
	devc = sdi->priv;

	g_free(transfer->buffer);
	transfer->buffer = NULL;
	libusb_free_transfer(transfer);

	for (i = 0; i < BULK_IN_TRANSFERS_NUM; i++) {
		if (devc->transfers[i] == transfer) {
			sr_spew("free_transfer: %d.", i);
			devc->transfers[i] = NULL;
			break;
		}
	}

	devc->submitted_transfers--;
	if (devc->submitted_transfers == 0)
		finish_acquisition(sdi);
}

static void resubmit_transfer(struct libusb_transfer *transfer)
{
	int ret;

	if ((ret = libusb_submit_transfer(transfer)) == LIBUSB_SUCCESS)
		return;

	free_transfer(transfer);
}

static size_t bytes_per_ms(struct dev_context *devc)
{
	return devc->cur_samplerate * devc->digital_channel_select_num / 8000;
}

static size_t get_buffer_size(struct dev_context *devc)
{
	// The buffer should be large enough to hold 20ms of data
	size_t s = bytes_per_ms(devc) * 20;

	if (s <= 20 * 1024)
		return (s + 511) & ~511;
	else
		return (s / (20 * 1024) + 1) * (20 * 1024);
}

static uint32_t get_timeout(struct dev_context *devc)
{
	size_t total_size;
	unsigned int timeout;

	total_size = get_buffer_size(devc) * BULK_IN_TRANSFERS_NUM;
	timeout = total_size / bytes_per_ms(devc);
	return timeout + timeout / 4; /* Leave a headroom of 25% percent. */
}

static int configure_requested_channels(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc;
	struct sr_channel *ch;
	GSList *l;

	devc = sdi->priv;

	devc->digital_channel_select_mask = 0;

	for (l = sdi->channels; l; l = l->next) {
		ch = (struct sr_channel *)l->data;

		if (ch->enabled == TRUE)
			devc->digital_channel_select_mask |= 0x1ul << (ch->index);
	}

	return SR_OK;
}

static size_t convert_sample_logic_u8(struct dev_context *devc,
	uint8_t *dest, const uint8_t *src, size_t srccnt)
{
	size_t ret = 0;
	uint32_t ch, byte, bit;
	uint8_t channel_data[256];
	uint16_t *ch_masks = devc->digital_channel_masks;
	uint32_t ch_num = devc->digital_channel_select_num;
	uint32_t unitbits = devc->lpc43xx_registers.in_pkt_info.logic_unitbits;

	srccnt /= (unitbits / 8) * ch_num;
	while (srccnt--) {
		memset(channel_data, 0, unitbits);
		for (ch = 0; ch < ch_num; ch++) {
			for (byte = 0; byte < (unitbits / 8); byte++) {
				uint8_t sample = *src++;
				for (bit = 0; bit < 8; bit++, sample >>= 1) {
					if (sample & 0x1)
						channel_data[byte * 8 + bit] |= ch_masks[ch];
				}
			}
		}
		memcpy(dest, channel_data, unitbits);
		dest += unitbits;
		ret += unitbits;
	}

	return ret;
}

static size_t convert_sample_logic_u16(struct dev_context *devc,
	uint8_t *dest, const uint8_t *src, size_t srccnt)
{
	size_t ret = 0;
	uint32_t ch, bit;
	uint16_t channel_data[32];
	uint16_t *ch_masks = devc->digital_channel_masks;
	uint32_t ch_num = devc->digital_channel_select_num;
	const uint32_t *src32 = (const uint32_t *)src;

	srccnt /= 4 * ch_num;
	while (srccnt--) {
		memset(channel_data, 0, sizeof(channel_data));
		for (ch = 0; ch < ch_num; ch++) {
			uint32_t sample = *src32++;
			for (bit = 0; bit < 32; bit++, sample >>= 1) {
				if (sample & 0x1)
					channel_data[bit] |= ch_masks[ch];
			}
		}
		memcpy(dest, channel_data, sizeof(channel_data));
		dest += sizeof(channel_data);
		ret += 32;
	}

	return ret;
}

#if 0
static size_t convert_sample_data(struct dev_context *devc,
	uint8_t *dest, size_t destcnt, const uint8_t *src, size_t srccnt)
{
	uint16_t channel_data[32];
	uint32_t i, unitsize, unitshift;
	size_t ret = 0;

	(void)destcnt;

	unitsize = devc->lpc43xx_registers.in_pkt_info.logic_unitbits *
		devc->lpc43xx_registers.in_pkt_info.logic_unitchs / 8;
	unitshift = devc->lpc43xx_registers.in_pkt_info.logic_unitbits / 8;

	srccnt /= unitsize;

#if 1
	while (srccnt--) {
		uint32_t ch, shift;

		for (shift = 0; shift < devc->lpc43xx_registers.in_pkt_info.logic_unitbits / 8; shift += 4) {
			memset(channel_data, 0, 2 * 32);
			for (ch = 0; ch < devc->lpc43xx_registers.in_pkt_info.logic_unitchs; ch++) {
				uint32_t sample = *(uint32_t *)(src + unitshift * ch + shift);
				uint16_t channel_mask = devc->digital_channel_masks[ch];
				for (i = 0; i < 32; i++, sample >>= 1) {
					if (sample & 0x1)
						channel_data[i] |= channel_mask;
				}
			}
			memcpy(dest, channel_data, 2 * 32);
			dest += 2 * 32;
			ret += 32;
		}
		src += unitsize;
	}
#else
	ret = srccnt * devc->lpc43xx_registers.in_pkt_info.logic_unitbits;
#endif

	return ret;
}
#endif


static void *convert_thread_do(void *p)
{
	int sample_count;
	const struct sr_dev_inst *sdi = p;
	struct dev_context *devc = sdi->priv;

	while (!devc->acq_aborted) {
		pthread_cond_wait(&devc->convert_cond, &devc->convert_mutex);

		sample_count = devc->convert_sample(devc, devc->convbuffer,
			devc->transferbuffer, devc->actual_length);

		if (devc->limit_samples && devc->sent_samples + sample_count > devc->limit_samples)
			sample_count = devc->limit_samples - devc->sent_samples;
		devc->sent_samples += sample_count;

		pthread_mutex_lock(&devc->out_mutex);
		devc->out_length = (devc->lpc43xx_registers.in_pkt_info.logic_unitbits == 32) ?
			sample_count * 2 : sample_count;
		memcpy(devc->outbuffer, devc->convbuffer, devc->out_length);
		pthread_cond_signal(&devc->out_cond);
		pthread_mutex_unlock(&devc->out_mutex);

		pthread_mutex_unlock(&devc->convert_mutex);
	}

	pthread_mutex_destroy(&devc->convert_mutex);
	pthread_cond_destroy(&devc->convert_cond);
	pthread_exit(NULL);
	return NULL;
}

static void *out_thread_do(void *p)
{
	struct sr_datafeed_packet packet;
	struct sr_datafeed_logic logic;
	const struct sr_dev_inst *sdi = p;
	struct dev_context *devc = sdi->priv;

	while (!devc->acq_aborted) {
		pthread_cond_wait(&devc->out_cond, &devc->out_mutex);

		packet.type = SR_DF_LOGIC;
		packet.payload = &logic;
		logic.unitsize = devc->lpc43xx_registers.in_pkt_info.logic_unitbits == 32 ? 2 : 1;
		logic.length = devc->out_length;
		logic.data = devc->outbuffer;
		sr_session_send(sdi, &packet);

		pthread_mutex_unlock(&devc->out_mutex);
	}

	pthread_mutex_destroy(&devc->out_mutex);
	pthread_cond_destroy(&devc->out_cond);
	pthread_exit(NULL);
	return NULL;
}

static void receive_transfer(struct libusb_transfer *transfer)
{
	struct sr_dev_inst *sdi;
	struct dev_context *devc;
	gboolean packet_has_error = FALSE;
	int trigger_offset;

	sdi = transfer->user_data;
	devc = sdi->priv;

	if (devc->acq_aborted) {
		free_transfer(transfer);
		return;
	}

	switch (transfer->status) {
	case LIBUSB_TRANSFER_NO_DEVICE:
		abort_acquisition(devc);
		free_transfer(transfer);
		return;
	case LIBUSB_TRANSFER_COMPLETED:
	case LIBUSB_TRANSFER_TIMED_OUT:
		break;
	default:
		packet_has_error = TRUE;
		break;
	}

	if (transfer->actual_length == 0 || packet_has_error) {
		devc->empty_transfer_count++;
		if (devc->empty_transfer_count > (BULK_IN_TRANSFERS_NUM * 2)) {
			sr_err("receive_transfer: %d", devc->empty_transfer_count);
			abort_acquisition(devc);
			free_transfer(transfer);
		}
		else {
			resubmit_transfer(transfer);
		}
		return;
	}
	else {
		devc->empty_transfer_count = 0;
	}

	if (devc->trigger_fired) {
		if (!devc->limit_samples || devc->sent_samples < devc->limit_samples) {
#if 0
			int cur_sample_count;
			struct sr_datafeed_packet packet;
			struct sr_datafeed_logic logic;

			cur_sample_count = devc->convert_sample(devc, devc->convbuffer,
				transfer->buffer, transfer->actual_length);

			if (devc->limit_samples && devc->sent_samples + cur_sample_count > devc->limit_samples)
				cur_sample_count = devc->limit_samples - devc->sent_samples;

			packet.type = SR_DF_LOGIC;
			packet.payload = &logic;
			logic.unitsize = devc->lpc43xx_registers.in_pkt_info.logic_unitbits == 32 ? 2 : 1;
			logic.length = cur_sample_count * logic.unitsize;
			logic.data = devc->convbuffer;
			sr_session_send(sdi, &packet);
			devc->sent_samples += cur_sample_count;
#else
			pthread_mutex_lock(&devc->convert_mutex);
			devc->actual_length = transfer->actual_length;
			memcpy(devc->transferbuffer, transfer->buffer, transfer->actual_length);
			pthread_cond_signal(&devc->convert_cond);
			pthread_mutex_unlock(&devc->convert_mutex);
#endif
		}
	}
	else {
		(void)trigger_offset;
		// TODO
	}

	if (devc->limit_samples && devc->sent_samples >= devc->limit_samples) {
		sr_info("devc->sent_samples: %d", (int)devc->sent_samples);
		abort_acquisition(devc);
		free_transfer(transfer);
	}
	else
		resubmit_transfer(transfer);
}


SR_PRIV int vll_config_acquisition(const struct sr_dev_inst *sdi)
{
	struct sr_usb_dev_inst *usb;
	struct dev_context *devc;
	struct libusb_transfer *transfer;
	uint32_t i, j, status, timeout;
	int ret;

	devc = sdi->priv;
	usb = sdi->conn;

	configure_requested_channels(sdi);

	// Configure Vllogic paramter
	devc->lpc43xx_registers.command = VLLOGIC_CMD_CONFIG;
	devc->lpc43xx_registers.mode = VLLOGIC_MODE_IN;
	devc->lpc43xx_registers.rate = devc->cur_samplerate;
	devc->lpc43xx_registers.channels_in_enable_mask =
		devc->lpc43xx_registers.board_in_channels_mask &
		devc->digital_channel_select_mask;

	write_registers(usb, 0, sizeof(struct lpc43xx_registers_list_t) - sizeof(struct vllogic_in_pkt_info_t),
		(uint32_t *)&devc->lpc43xx_registers);

	read_registers(usb, 12, 4, &status);

	if (status == VLLOGIC_STATUS_CONFIG_DONE) {
		read_registers(usb, 0, sizeof(struct lpc43xx_registers_list_t) - sizeof(struct vllogic_in_pkt_info_t),
			(uint32_t *)&devc->lpc43xx_registers);
		read_registers(usb, 44, sizeof(struct vllogic_in_pkt_info_t),
			(uint32_t *)&devc->lpc43xx_registers.in_pkt_info);
	}
	else {
		sr_spew("vll_start_acquisition config failed, Status: %d.", status);
		return SR_ERR;
	}

	sr_spew("pkt_size: %d.", devc->lpc43xx_registers.in_pkt_info.pkt_size);
	
	devc->digital_channel_select_num = 0;
	for (i = 0, j = 0; i < 16; i++) {
		if (devc->lpc43xx_registers.channels_in_enable_mask & (0x1ul << i)) {
			devc->digital_channel_select_num++;
			devc->digital_channel_masks[j++] = 0x1ul << i;
		}
	}
	sr_spew("digital_channel_select_num: %d.", devc->digital_channel_select_num);

	switch (devc->lpc43xx_registers.in_pkt_info.logic_unitbits) {
	case 32:
		devc->convert_sample = convert_sample_logic_u16;
		break;
	case 64:
	case 128:
	case 256:
		devc->convert_sample = convert_sample_logic_u8;
		break;
	default:
		sr_spew("vll_start_acquisition config failed, logic_unitbits: %d.",
			devc->lpc43xx_registers.in_pkt_info.logic_unitbits);
		return SR_ERR;
	}
	sr_spew("logic_unitbits: %d.", devc->lpc43xx_registers.in_pkt_info.logic_unitbits);

	devc->transferbuffer_size = get_buffer_size(devc);
	if (!(devc->transferbuffer = g_try_malloc(devc->transferbuffer_size))) {
		sr_err("transferbuffer malloc failed.");
		return SR_ERR_MALLOC;
	}
	devc->convbuffer_size = devc->transferbuffer_size * 16 / devc->lpc43xx_registers.in_pkt_info.logic_unitchs + 2 * 32;
	if (!(devc->convbuffer = g_try_malloc(devc->convbuffer_size * 2))) {
		g_free(devc->transferbuffer);
		sr_err("Conversion buffer malloc failed.");
		return SR_ERR_MALLOC;
	}
	devc->outbuffer = devc->convbuffer + devc->convbuffer_size;

	timeout = get_timeout(devc);
	sr_spew("timeout: %d.", timeout);
	devc->submitted_transfers = 0;
	memset(devc->transfers, 0, sizeof(struct libusb_transfer *) * BULK_IN_TRANSFERS_NUM);

	for (i = 0; i < BULK_IN_TRANSFERS_NUM; i++) {
		uint8_t *buf;
		if (!(buf = g_try_malloc(devc->transferbuffer_size))) {
			sr_err("USB transfer buffer malloc failed.");
			if (devc->submitted_transfers)
				abort_acquisition(devc);
			else {
				g_free(devc->convbuffer);
			}
			return SR_ERR_MALLOC;
		}
		transfer = libusb_alloc_transfer(0);
		libusb_fill_bulk_transfer(transfer, usb->devhdl,
			VLLOGIC_IN_EP | LIBUSB_ENDPOINT_IN, buf, devc->transferbuffer_size,
			receive_transfer, (void *)sdi, timeout);
		if ((ret = libusb_submit_transfer(transfer)) != 0) {
			sr_err("Failed to submit transfer: %s.", libusb_error_name(ret));
			libusb_free_transfer(transfer);
			g_free(buf);
			abort_acquisition(devc);
			return SR_ERR;
		}
		devc->transfers[i] = transfer;
		devc->submitted_transfers++;
	}

	pthread_mutex_init(&devc->convert_mutex, NULL);
	pthread_cond_init(&devc->convert_cond, NULL);
	pthread_create(&devc->convert_thread, NULL, convert_thread_do, (void *)sdi);
	pthread_mutex_init(&devc->out_mutex, NULL);
	pthread_cond_init(&devc->out_cond, NULL);
	pthread_create(&devc->out_thread, NULL, out_thread_do, (void *)sdi);

	return SR_OK;
}

static int receive_data(int fd, int revents, void *cb_data)
{
	struct timeval tv;
	struct drv_context *drvc;

	(void)fd;
	(void)revents;

	drvc = (struct drv_context *)cb_data;

	tv.tv_sec = tv.tv_usec = 0;
	libusb_handle_events_timeout(drvc->sr_ctx->libusb_ctx, &tv);

	return TRUE;
}

SR_PRIV int vll_start_acquisition(const struct sr_dev_inst *sdi)
{
	int ret;
	struct sr_dev_driver *di = sdi->driver;
	struct drv_context *drvc = di->context;
	struct dev_context *devc = sdi->priv;
	struct sr_usb_dev_inst *usb = sdi->conn;

	devc->ctx = drvc->sr_ctx;
	devc->sent_samples = 0;
	devc->empty_transfer_count = 0;
	devc->acq_aborted = FALSE;
	devc->trigger_fired = TRUE;

	if ((ret = vll_config_acquisition(sdi)) < 0)
		return ret;

	usb_source_add(sdi->session, devc->ctx, 100, receive_data, drvc);
	std_session_send_df_header(sdi);

	// Start acquisition
	devc->lpc43xx_registers.command = VLLOGIC_CMD_START;
	if (write_registers(usb, 16, 4, &devc->lpc43xx_registers.command) != SR_OK) {
		abort_acquisition(devc);
		return SR_ERR;
	}

	return SR_OK;
}

SR_PRIV int vll_stop_acquisition(const struct sr_dev_inst *sdi)
{
	abort_acquisition(sdi->priv);

	return SR_OK;
}
