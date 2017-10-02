/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2017 Talpa Chen <talpachen@gmail.com>
 * Copyright (C) 2012 Bert Vermeulen <bert@biot.com>
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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "protocol.h"

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
};

static const uint32_t devopts[] = {
	SR_CONF_CONTINUOUS,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	//SR_CONF_OSCILLOSCOPE,
	//SR_CONF_VOLTAGE_THRESHOLD | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	//SR_CONF_TRIGGER_MATCH | SR_CONF_LIST,
	//SR_CONF_RLE | SR_CONF_GET | SR_CONF_SET,
};

static const int32_t trigger_matches[] = {
	SR_TRIGGER_ZERO,
	SR_TRIGGER_ONE,
	SR_TRIGGER_RISING,
	SR_TRIGGER_FALLING,
	//SR_TRIGGER_EDGE,
};

static const uint64_t samplerates[] = {
	SR_KHZ(50),
	SR_KHZ(100),
	SR_KHZ(200),
	SR_KHZ(500),
	SR_MHZ(1),
	SR_MHZ(2),
	SR_MHZ(5),
	SR_MHZ(10),
	SR_MHZ(25),
	SR_MHZ(50),
	SR_MHZ(80),
	SR_MHZ(100),
	SR_MHZ(120),
	SR_MHZ(160),
	SR_MHZ(200),
	SR_MHZ(240),
};

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	struct sr_dev_inst *sdi;
	struct drv_context *drvc;
	struct dev_context *devc;
	struct sr_usb_dev_inst *usb;
	struct libusb_device_descriptor des;
	libusb_device **devlist;
	GSList *devices;
	char channel_name[8];
	char connection_id[64];
	uint32_t i, j;

	(void)options;

	devices = NULL;

	drvc = di->context;

	libusb_get_device_list(drvc->sr_ctx->libusb_ctx, &devlist);

	for (i = 0; devlist[i]; i++) {
		libusb_get_device_descriptor(devlist[i], &des);

		if (des.idVendor != VLLOGIC_VID)
			continue;

		usb_get_port_path(devlist[i], connection_id, sizeof(connection_id));

		usb = NULL;

		switch (des.idProduct) {
		case VL1602XX_PID:
			usb = sr_usb_dev_inst_new(libusb_get_bus_number(devlist[i]),
				libusb_get_device_address(devlist[i]), NULL);

			if (!usb)
				break;

			if (libusb_open(devlist[i], &usb->devhdl)) {
				sr_usb_dev_inst_free(usb);
				break;
			}
			devc = vll_new_device(drvc, usb);

			devc->cur_samplerate = samplerates[0];

			libusb_close(usb->devhdl);
			usb->devhdl = NULL;

			if (!devc) {
				sr_usb_dev_inst_free(usb);
				usb = NULL;
				break;
			}

			sdi = g_malloc0(sizeof(struct sr_dev_inst));
			sdi->status = SR_ST_INACTIVE;
			sdi->vendor = g_strdup(devc->vendor);
			sdi->model = g_strdup(devc->model);
			sdi->connection_id = g_strdup(connection_id);
			sdi->inst_type = SR_INST_USB;
			sdi->conn = usb;
			sdi->priv = devc;

			for (j = 0; j < devc->digital_channel_num; j++) {
				sprintf(channel_name, "D%d", j);
				sr_channel_new(sdi, j, SR_CHANNEL_LOGIC,
					TRUE, channel_name);
			}

			for (j = 0; j < devc->analog_channel_num; j++) {
				sprintf(channel_name, "A%d", j);
				sr_channel_new(sdi, devc->analog_channel_num + j,
					SR_CHANNEL_ANALOG, TRUE, channel_name);
			}

			devices = g_slist_append(devices, sdi);
			break;
		default:
			break;
		}
	}

	libusb_free_device_list(devlist, 1);
	return std_scan_complete(di, devices);
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;

	(void)cg;

	if (!sdi)
		return SR_ERR_ARG;

	devc = sdi->priv;

	switch (key) {
	case SR_CONF_LIMIT_SAMPLES:
		*data = g_variant_new_uint64(devc->limit_samples);
		break;
	case SR_CONF_SAMPLERATE:
		*data = g_variant_new_uint64(devc->cur_samplerate);
		break;
	case SR_CONF_VOLTAGE_THRESHOLD:
		// TODO
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;

	(void)cg;

	if (!sdi)
		return SR_ERR_ARG;

	devc = sdi->priv;

	switch (key) {
	case SR_CONF_LIMIT_SAMPLES:
		devc->limit_samples = g_variant_get_uint64(data);
		break;
	case SR_CONF_SAMPLERATE:
		devc->cur_samplerate = g_variant_get_uint64(data);
		break;
	case SR_CONF_VOLTAGE_THRESHOLD:
		// TODO
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	//GVariant *gvar;

	switch (key) {
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
	case SR_CONF_SAMPLERATE:
		*data = std_gvar_samplerates(samplerates, ARRAY_SIZE(samplerates));
		break;
	case SR_CONF_VOLTAGE_THRESHOLD:
		// TODO
		break;
	case SR_CONF_TRIGGER_MATCH:
		// TODO
		break;
	default:
		return SR_ERR_NA;
	}

	return SR_OK;
}

static void clear_helper(struct dev_context *devc)
{
	(void)devc;
	// TODO
}

static int dev_clear(const struct sr_dev_driver *di)
{
	return std_dev_clear_with_callback(di, (std_dev_clear_callback)clear_helper);
}

static int dev_open(struct sr_dev_inst *sdi)
{
	int ret;
	struct sr_dev_driver *di = sdi->driver;
	struct drv_context *drvc = di->context;
	struct sr_usb_dev_inst *usb = sdi->conn;

	if (sr_usb_open(drvc->sr_ctx->libusb_ctx, usb) != SR_OK)
		return SR_ERR;

	if (libusb_kernel_driver_active(usb->devhdl, VLLOGIC_INTERFACE) == 1) {
		ret = libusb_detach_kernel_driver(usb->devhdl, VLLOGIC_INTERFACE);
		if (ret < 0) {
			sr_err("Failed to detach kernel driver: %s.", libusb_error_name(ret));
			return SR_ERR;
		}
	}

	if ((ret = libusb_claim_interface(usb->devhdl, VLLOGIC_INTERFACE)) < 0) {
		sr_err("Failed to claim interface: %s.", libusb_error_name(ret));
		return SR_ERR;
	}

	sdi->status = SR_ST_ACTIVE;
	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	struct sr_usb_dev_inst *usb;

	usb = sdi->conn;

	if (!usb->devhdl)
		return SR_ERR_BUG;

	libusb_release_interface(usb->devhdl, VLLOGIC_INTERFACE);
	libusb_close(usb->devhdl);
	usb->devhdl = NULL;

	return SR_OK;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	return vll_start_acquisition(sdi);
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	return vll_stop_acquisition(sdi);
}

SR_PRIV struct sr_dev_driver vllogic_driver_info = {
	.name = "vllogic",
	.longname = "Vllogic (https://github.com/vllogic)",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(vllogic_driver_info);
