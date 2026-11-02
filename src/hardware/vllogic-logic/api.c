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

#include <config.h>

#include <inttypes.h>
#include <math.h>
#include <string.h>

#include <glib.h>
#include <libusb.h>
#include <libsigrok/libsigrok.h>

#include "vllogic.h"

/* ------------------------------------------------------------------------- */
/* Samplerate table                                                          */
/* ------------------------------------------------------------------------- */

/*
 * Rates below 20 MHz keep the hardware at div=120 and decimate in the
 * parser output domain.  1 MHz is the legacy phase-A rate; 10/5/2.5 MHz are
 * the documented PC decimation tiers.
 */
struct vllogic_rate {
	uint64_t rate;
	uint32_t div;
	uint32_t decimate;
};

static const struct vllogic_rate vllogic_rates[] = {
	{ 1000000ull,		120,	20 },
	{ 2500000ull,		120,	8 },
	{ 5000000ull,		120,	4 },
	{ 10000000ull,		120,	2 },
	{ SR_MHZ(20),		120,	1 },
	{ SR_MHZ(24),		100,	1 },
	{ SR_MHZ(30),		80,	1 },
	{ SR_MHZ(40),		60,	1 },
	{ SR_MHZ(48),		50,	1 },
	{ SR_MHZ(60),		40,	1 },
	{ SR_MHZ(80),		30,	1 },
	{ SR_MHZ(96),		25,	1 },
	{ SR_MHZ(100),		24,	1 },
	{ SR_MHZ(120),		20,	1 },
	{ SR_MHZ(150),		16,	1 },
	{ SR_MHZ(200),		12,	1 },
	{ SR_MHZ(240),		10,	1 },
	{ SR_MHZ(300),		8,	1 },
	{ SR_MHZ(400),		6,	1 },
	{ SR_MHZ(480),		5,	1 },
	{ SR_MHZ(600),		4,	1 },
	{ SR_MHZ(800),		3,	1 },
	{ SR_MHZ(1200),		2,	1 },
};

#define VLLOGIC_NUM_RATES \
	(sizeof(vllogic_rates) / sizeof(vllogic_rates[0]))

/* Highest channel count the FPGA can sustain at a given output rate. */
static int vllogic_max_channels(uint64_t rate)
{
	if (rate > SR_MHZ(800))
		return 2;
	if (rate > SR_MHZ(400))
		return 4;
	if (rate > SR_MHZ(200))
		return 8;
	if (rate > SR_MHZ(160))
		return 16;

	return VLLOGIC_NUM_CHANNELS;
}

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
};

static const uint32_t devopts[] = {
	SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_VOLTAGE_THRESHOLD | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	SR_CONF_CONN | SR_CONF_GET,
};

/* LIST payload, filled once from vllogic_rates[]. */
static uint64_t samplerates[VLLOGIC_NUM_RATES];
static gsize samplerates_ready;

static const uint64_t *vllogic_samplerates(void)
{
	if (g_once_init_enter(&samplerates_ready)) {
		size_t i;

		for (i = 0; i < VLLOGIC_NUM_RATES; i++)
			samplerates[i] = vllogic_rates[i].rate;
		g_once_init_leave(&samplerates_ready, 1);
	}

	return samplerates;
}

static struct sr_dev_driver vllogic_logic_driver_info;

/* ------------------------------------------------------------------------- */
/* Scan                                                                      */
/* ------------------------------------------------------------------------- */

/**
 * Check whether this 1209:6688 device is a Logic20 and not a USB Sniffer 2.
 *
 * The VID:PID pair is shared by both firmware images, and their UHSIF
 * versions (v2.2 vs v2.3) are not compatible, so the device has to be
 * disambiguated here.  bcdDevice is authoritative and needs no permissions;
 * the product string is checked as well when the device can be opened.
 */
static gboolean vllogic_match(libusb_device *dev,
		const struct libusb_device_descriptor *des, char *serial,
		size_t serial_len)
{
	libusb_device_handle *hdl = NULL;
	unsigned char buf[128];
	gboolean ok = TRUE;

	if (des->bcdDevice != VLLOGIC_BCD_LOGIC20)
		return FALSE;

	if (libusb_open(dev, &hdl) != 0) {
		/* No permissions needed for the check above: accept it. */
		sr_dbg("Cannot open device to verify its product string.");
		return TRUE;
	}

	if (des->iProduct) {
		int n = libusb_get_string_descriptor_ascii(hdl, des->iProduct,
				buf, (int)sizeof(buf) - 1);

		if (n > 0) {
			buf[n] = '\0';
			if (strcmp((const char *)buf,
				   VLLOGIC_PRODUCT_LOGIC20) != 0) {
				sr_dbg("Ignoring 1209:6688 device '%s' "
				       "(bcdDevice 0x%04x).",
				       (const char *)buf, des->bcdDevice);
				ok = FALSE;
			}
		}
	}

	if (ok && serial && serial_len > 0 && des->iSerialNumber) {
		int n = libusb_get_string_descriptor_ascii(hdl,
				des->iSerialNumber, buf, (int)sizeof(buf) - 1);

		if (n > 0) {
			buf[n] = '\0';
			g_strlcpy(serial, (const char *)buf, serial_len);
		}
	}

	libusb_close(hdl);

	return ok;
}

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	struct drv_context *drvc = di->context;
	struct sr_dev_inst *sdi;
	struct sr_channel *ch;
	struct dev_context *devc;
	libusb_device **devlist;
	struct libusb_device_descriptor des;
	GSList *devices = NULL;
	GSList *conn_devices = NULL;
	const char *conn = NULL;
	GSList *l;
	int c, i;

	for (l = options; l; l = l->next) {
		struct sr_config *src = l->data;

		if (src->key == SR_CONF_CONN) {
			conn = g_variant_get_string(src->data, NULL);
			break;
		}
	}

	if (conn && *conn) {
		sr_info("Scanning for %s.", conn);
		conn_devices = sr_usb_find(drvc->sr_ctx->libusb_ctx, conn);
		if (!conn_devices) {
			sr_err("No matching USB device found.");
			return NULL;
		}
	}

	if (libusb_get_device_list(drvc->sr_ctx->libusb_ctx, &devlist) < 0) {
		sr_err("Failed to get the USB device list.");
		g_slist_free_full(conn_devices, (GDestroyNotify)sr_usb_dev_inst_free);
		return NULL;
	}

	for (i = 0; devlist[i]; i++) {
		char connection_id[64];
		char serial[64] = "";

		if (conn_devices) {
			struct sr_usb_dev_inst *usb = NULL;

			for (l = conn_devices; l; l = l->next) {
				usb = l->data;
				if (usb->bus == libusb_get_bus_number(devlist[i]) &&
				    usb->address ==
				    libusb_get_device_address(devlist[i]))
					break;
			}
			if (!l)
				continue;
		}

		if (libusb_get_device_descriptor(devlist[i], &des) < 0)
			continue;
		if (des.idVendor != VLLOGIC_VID ||
		    des.idProduct != VLLOGIC_PID)
			continue;
		if (!vllogic_match(devlist[i], &des, serial, sizeof(serial)))
			continue;

		if (usb_get_port_path(devlist[i], connection_id,
				      (int)sizeof(connection_id)) < 0)
			g_snprintf(connection_id, sizeof(connection_id), "%d.%d",
				   libusb_get_bus_number(devlist[i]),
				   libusb_get_device_address(devlist[i]));

		sdi = g_malloc0(sizeof(*sdi));
		sdi->driver = &vllogic_logic_driver_info;
		sdi->vendor = g_strdup("VLLogic");
		sdi->model = g_strdup("Logic20");
		sdi->version = g_strdup_printf("0x%04x", des.bcdDevice);
		if (serial[0])
			sdi->serial_num = g_strdup(serial);
		sdi->connection_id = g_strdup(connection_id);

		for (c = 0; c < VLLOGIC_NUM_CHANNELS; c++) {
			char name[8];

			g_snprintf(name, sizeof(name), "%d", c);
			ch = sr_channel_new(sdi, c, SR_CHANNEL_LOGIC, TRUE,
					name);
			(void)ch;
		}

		devc = g_malloc0(sizeof(*devc));
		devc->div = VLLOGIC_DIV_MAX;
		devc->decimate = 1;
		devc->samplerate = VLLOGIC_CLOCK_HZ / devc->div;
		devc->limit_samples = 0;
		devc->pwm0 = VLLOGIC_PWM_DEFAULT0;
		devc->pwm1 = VLLOGIC_PWM_DEFAULT1;
		/*
		 * pwm0=19 maps to ~1.6412 V; nearest 0.05 V grid point is
		 * index 83.  Use the very same expression as config_list() so
		 * the default is bit-identical to LIST[83] (a literal 1.65
		 * differs by 4.4e-16, which is exactly PulseView's tolerance).
		 */
		devc->cur_threshold = -2.5 + 83 * 0.05;
		atomic_store_explicit(&devc->state, VLLOGIC_IDLE, memory_order_relaxed);
		devc->usb_ctx = NULL;

		sdi->priv = devc;
		sdi->status = SR_ST_INACTIVE;
		sdi->inst_type = SR_INST_USB;
		sdi->conn = sr_usb_dev_inst_new(libusb_get_bus_number(devlist[i]),
				libusb_get_device_address(devlist[i]), NULL);

		devices = g_slist_append(devices, sdi);
	}

	libusb_free_device_list(devlist, 1);
	g_slist_free_full(conn_devices, (GDestroyNotify)sr_usb_dev_inst_free);

	return std_scan_complete(di, devices);
}

/* ------------------------------------------------------------------------- */
/* Configuration persistence                                                 */
/* ------------------------------------------------------------------------- */

/*
 * Per-device settings live in <user-config-dir>/vllogic-logic/config.ini:
 *   Linux   ~/.config/vllogic-logic/config.ini
 *   Windows %APPDATA%\vllogic-logic\config.ini
 *   macOS   ~/Library/Application Support/vllogic-logic/config.ini
 * Only GLib APIs are used, so there is no platform-specific code.
 */
#define VLLOGIC_CONF_VERSION	1
#define VLLOGIC_CONF_DEFAULT_RATE	SR_MHZ(20)

static gboolean conf_disabled(void)
{
	const char *e = getenv("VLLOGIC_NO_SAVE");

	return e && e[0] == '1' && e[1] == '\0';
}

/* INI group name: serial number, else connection id, sanitised. */
static char *conf_group(const struct sr_dev_inst *sdi)
{
	const char *src = NULL;
	char *g, *p;

	if (sdi->serial_num && *sdi->serial_num)
		src = sdi->serial_num;
	else if (sdi->connection_id && *sdi->connection_id)
		src = sdi->connection_id;
	else
		src = "default";

	g = g_strdup(src);
	for (p = g; *p; p++) {
		if (*p == '[' || *p == ']' || *p == '=' || *p == ';' ||
		    *p == '#' || *p == '/')
			*p = '_';
	}

	return g;
}

static char *conf_path(void)
{
	char *dir = g_build_filename(g_get_user_config_dir(),
			"vllogic-logic", NULL);
	char *path;

	g_mkdir_with_parents(dir, 0700);
	path = g_build_filename(dir, "config.ini", NULL);
	g_free(dir);

	return path;
}

static gboolean conf_apply_rate(struct dev_context *devc, uint64_t rate)
{
	unsigned int i;

	for (i = 0; i < VLLOGIC_NUM_RATES; i++)
		if (vllogic_rates[i].rate == rate) {
			devc->div = vllogic_rates[i].div;
			devc->decimate = vllogic_rates[i].decimate;
			devc->samplerate = rate;
			return TRUE;
		}

	return FALSE;
}

/* Quantise to the 0.05 V grid used by config_list()/config_set(). */
static double conf_quantise_threshold(double vth)
{
	long idx = lround((vth + 2.5) / 0.05);

	if (idx < 0)
		idx = 0;
	if (idx > 150)
		idx = 150;

	return -2.5 + (double)idx * 0.05;
}

static gboolean conf_rate_valid(uint64_t rate)
{
	unsigned int i;

	for (i = 0; i < VLLOGIC_NUM_RATES; i++)
		if (vllogic_rates[i].rate == rate)
			return TRUE;

	return FALSE;
}

/* Enabled channel indices as "0,1,2" (all 20 -> empty string is not used). */
static char *conf_channels_string(const struct sr_dev_inst *sdi)
{
	GString *s = g_string_new(NULL);
	GSList *l;

	for (l = sdi->channels; l; l = l->next) {
		struct sr_channel *ch = l->data;

		if (ch->type != SR_CHANNEL_LOGIC || !ch->enabled)
			continue;
		if (s->len)
			g_string_append_c(s, ',');
		g_string_append_printf(s, "%d", ch->index);
	}

	return g_string_free(s, FALSE);
}

static void conf_set_channels(struct sr_dev_inst *sdi, const gboolean *want)
{
	GSList *l;

	for (l = sdi->channels; l; l = l->next) {
		struct sr_channel *ch = l->data;

		if (ch->type != SR_CHANNEL_LOGIC)
			continue;
		ch->enabled = (ch->index >= 0 &&
			       ch->index < VLLOGIC_NUM_CHANNELS) ?
				want[ch->index] : FALSE;
	}
}

/* Rough admission check: full precision happens at start-up. */
/* Static link ceiling: 400 MB/s on SuperSpeed, 35 on HighSpeed, 5 else. */
static uint64_t conf_link_limit(const struct sr_dev_inst *sdi)
{
	struct sr_usb_dev_inst *usb = sdi->conn;
	libusb_device *udev = (usb && usb->devhdl) ?
			libusb_get_device(usb->devhdl) : NULL;
	int speed = udev ? libusb_get_device_speed(udev) : -1;
	uint64_t limit = 5ull * 1000 * 1000;
	const char *env = getenv("VLLOGIC_MAX_MBPS");

	if (speed == LIBUSB_SPEED_SUPER || speed == LIBUSB_SPEED_SUPER_PLUS)
		limit = 400ull * 1000 * 1000;
	else if (speed == LIBUSB_SPEED_HIGH)
		limit = 35ull * 1000 * 1000;

	if (env && *env) {
		uint64_t o = strtoull(env, NULL, 10) * 1000000ull;

		if (o > 0)
			limit = o;
	}

	return limit;
}

/*
 * Wire rate for a samplerate entry: decimation is applied in the host, the
 * ISERDES still runs at VLLOGIC_CLOCK_HZ / div.  The 1/2.5/5/10 MHz entries
 * all use div=120, i.e. 20 MHz on the wire - never the lower output rate.
 */
static uint64_t conf_hw_rate(uint64_t rate)
{
	unsigned int i;

	for (i = 0; i < VLLOGIC_NUM_RATES; i++)
		if (vllogic_rates[i].rate == rate)
			return VLLOGIC_CLOCK_HZ / vllogic_rates[i].div;

	return VLLOGIC_CLOCK_HZ / VLLOGIC_DIV_MAX;
}

static gboolean conf_bandwidth_ok(const struct sr_dev_inst *sdi,
		uint64_t rate, int nchan)
{
	uint64_t required = conf_hw_rate(rate) * (uint64_t)nchan / 8u;

	return required <= conf_link_limit(sdi);
}

/* Highest entry in vllogic_rates[] the selected channels can sustain. */
static uint64_t conf_max_rate_for(const struct sr_dev_inst *sdi, int nchan)
{
	uint64_t limit = conf_link_limit(sdi);
	int i;

	for (i = (int)VLLOGIC_NUM_RATES - 1; i >= 0; i--) {
		uint64_t rate = vllogic_rates[i].rate;
		uint64_t hw = VLLOGIC_CLOCK_HZ / vllogic_rates[i].div;

		if (nchan <= vllogic_max_channels(rate) &&
		    hw * (uint64_t)nchan / 8u <= limit)
			return rate;
	}

	sr_warn("config: no samplerate fits %d channels within %" PRIu64
		" MB/s; using the lowest entry.", nchan, limit / 1000000);

	return vllogic_rates[0].rate;
}

/**
 * Load <user-config-dir>/vllogic-logic/config.ini for this device.
 *
 * Invalid values fall back to defaults one key at a time; a bandwidth
 * mismatch resets the whole group (the combination is what is invalid).
 */
static void vllogic_conf_load(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	GKeyFile *kf;
	char *path, *group, *chans = NULL;
	GError *err = NULL;
	gboolean want[VLLOGIC_NUM_CHANNELS];
	int i, nchan = 0;
	double vth;
	uint64_t rate;
	gboolean fellback = FALSE;

	if (conf_disabled())
		return;

	path = conf_path();
	if (!g_file_test(path, G_FILE_TEST_EXISTS)) {
		sr_info("config: using defaults (no %s yet).", path);
		g_free(path);
		return;
	}

	kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, path, G_KEY_FILE_NONE, &err)) {
		/* Cannot attribute anything: whole-group fallback. */
		sr_warn("config: cannot parse %s (%s); using defaults.",
			path, err ? err->message : "unknown");
		g_clear_error(&err);
		g_key_file_free(kf);
		g_free(path);
		return;
	}

	group = conf_group(sdi);
	for (i = 0; i < VLLOGIC_NUM_CHANNELS; i++)
		want[i] = TRUE;

	/* channels (per-key fallback) */
	chans = g_key_file_get_string(kf, group, "channels", NULL);
	if (chans && *chans) {
		gchar **parts = g_strsplit(chans, ",", -1);
		gboolean any = FALSE;

		for (i = 0; i < VLLOGIC_NUM_CHANNELS; i++)
			want[i] = FALSE;
		for (i = 0; parts[i]; i++) {
			char *end = NULL;
			long v = strtol(parts[i], &end, 10);

			if (end == parts[i] || *end != '\0' || v < 0 ||
			    v >= VLLOGIC_NUM_CHANNELS)
				continue;
			want[v] = TRUE;
			any = TRUE;
		}
		g_strfreev(parts);
		if (any) {
			for (i = 0; i < VLLOGIC_NUM_CHANNELS; i++)
				nchan += want[i];
		} else {
			sr_warn("config: channels '%s' has no valid index; "
				"enabling all %d.", chans,
				VLLOGIC_NUM_CHANNELS);
			for (i = 0; i < VLLOGIC_NUM_CHANNELS; i++)
				want[i] = TRUE;
			nchan = VLLOGIC_NUM_CHANNELS;
			fellback = TRUE;
		}
	} else {
		nchan = VLLOGIC_NUM_CHANNELS;
	}

	/* samplerate (per-key fallback) */
	rate = g_key_file_get_uint64(kf, group, "samplerate", NULL);
	if (rate == 0 || !conf_rate_valid(rate)) {
		uint64_t best = conf_max_rate_for(sdi, nchan);

		sr_warn("config: samplerate %" G_GUINT64_FORMAT " is not "
			"supported; using %" G_GUINT64_FORMAT " Hz (max for "
			"%d ch).", rate, best, nchan);
		rate = best;
		fellback = TRUE;
	}
	(void)conf_apply_rate(devc, rate);

	/* limit_samples: uint64, no invalid values */
	devc->limit_samples = g_key_file_get_uint64(kf, group,
			"limit_samples", NULL);

	/* threshold (per-key fallback) */
	vth = g_key_file_get_double(kf, group, "threshold", NULL);
	if (!isfinite(vth) || vth < -2.5 || vth > 5.0) {
		sr_warn("config: threshold %.3f V out of range; using 1.65 V.",
			vth);
		vth = -2.5 + 83 * 0.05;
		fellback = TRUE;
	}
	devc->cur_threshold = conf_quantise_threshold(vth);
	if (vllogic_vth_to_pwm(devc->cur_threshold, &devc->pwm0,
			       &devc->pwm1) != 0) {
		devc->pwm0 = VLLOGIC_PWM_DEFAULT0;
		devc->pwm1 = VLLOGIC_PWM_DEFAULT1;
		fellback = TRUE;
	}

	/*
	 * Bandwidth / per-rate channel cap: keep threshold, limit and the
	 * channel set; only the samplerate is lowered.  If even the default
	 * rate cannot carry the selection, widen the channels as a last
	 * resort.
	 */
	if (nchan > vllogic_max_channels(rate) ||
	    !conf_bandwidth_ok(sdi, rate, nchan)) {
		uint64_t best = conf_max_rate_for(sdi, nchan);

		sr_warn("config: %" G_GUINT64_FORMAT " Hz x %d ch exceeds the "
			"link cap; samplerate lowered to %" G_GUINT64_FORMAT
			" Hz (max for %d ch).", rate, nchan, best, nchan);
		rate = best;
		(void)conf_apply_rate(devc, rate);
		fellback = TRUE;

		if (nchan > vllogic_max_channels(rate) ||
		    !conf_bandwidth_ok(sdi, rate, nchan)) {
			sr_warn("config: even %" G_GUINT64_FORMAT " Hz x %d ch "
				"does not fit; enabling all %d channels.",
				rate, nchan, VLLOGIC_NUM_CHANNELS);
			for (i = 0; i < VLLOGIC_NUM_CHANNELS; i++)
				want[i] = TRUE;
			nchan = VLLOGIC_NUM_CHANNELS;
			fellback = TRUE;

			/*
			 * Decimation cannot lower the wire rate (every
			 * 1/2.5/5/10 MHz entry still runs at 20 MHz), so
			 * the link cap may remain unsatisfied.  Leave the
			 * settings as loaded and let the start-time check
			 * refuse until the user cuts channels/rate.
			 */
			if (!conf_bandwidth_ok(sdi, rate, nchan))
				sr_warn("config: %" G_GUINT64_FORMAT " Hz x %d ch "
					"still exceeds the link cap; capture "
					"start will be refused until the channel "
					"count or samplerate is reduced.",
					rate, nchan);
		}
	}
	devc->samplerate = rate;

	conf_set_channels(sdi, want);
	sr_info("config: loaded %s (threshold=%.2f, samplerate=%"
		G_GUINT64_FORMAT ", limit=%" G_GUINT64_FORMAT
		", channels=%s)%s.", path, devc->cur_threshold,
		devc->samplerate, devc->limit_samples,
		chans ? chans : "0-19",
		fellback ? " with fallbacks" : "");

	g_free(chans);
	g_free(group);
	g_key_file_free(kf);
	g_free(path);
}

static void vllogic_conf_save(struct sr_dev_inst *sdi)
{
	GKeyFile *kf;
	char *path, *group, *chans, *data;
	gsize len = 0;
	GError *err = NULL;

	if (conf_disabled())
		return;

	path = conf_path();
	group = conf_group(sdi);
	chans = conf_channels_string(sdi);

	kf = g_key_file_new();
	g_key_file_set_integer(kf, group, "version", VLLOGIC_CONF_VERSION);
	g_key_file_set_double(kf, group, "threshold",
			((struct dev_context *)sdi->priv)->cur_threshold);
	g_key_file_set_uint64(kf, group, "samplerate",
			((struct dev_context *)sdi->priv)->samplerate);
	g_key_file_set_uint64(kf, group, "limit_samples",
			((struct dev_context *)sdi->priv)->limit_samples);
	g_key_file_set_string(kf, group, "channels", chans);

	data = g_key_file_to_data(kf, &len, NULL);
	if (!g_file_set_contents(path, data, (gssize)len, &err)) {
		sr_warn("config: cannot write %s (%s); settings will not "
			"persist.", path, err ? err->message : "unknown");
		g_clear_error(&err);
	}

	g_free(data);
	g_key_file_free(kf);
	g_free(chans);
	g_free(group);
	g_free(path);
}

/* ------------------------------------------------------------------------- */
/* Device life cycle                                                         */
/* ------------------------------------------------------------------------- */

static int dev_open(struct sr_dev_inst *sdi)
{
	struct drv_context *drvc = sdi->driver->context;
	struct sr_usb_dev_inst *usb = sdi->conn;
	struct dev_context *devc = sdi->priv;
	int ret;

	if (!usb) {
		sr_err("Invalid USB device instance.");
		return SR_ERR;
	}

	if (sr_usb_open(drvc->sr_ctx->libusb_ctx, usb) != SR_OK) {
		sr_err("Unable to open %s.", sdi->connection_id);
		return SR_ERR;
	}

	/* Do not call libusb_set_configuration(): re-issuing SET_CONFIGURATION
	 * on an already configured device wedges EP1 permanently. */
	libusb_set_auto_detach_kernel_driver(usb->devhdl, 1);

	ret = libusb_claim_interface(usb->devhdl, VLLOGIC_IFACE);
	if (ret != 0) {
		switch (ret) {
		case LIBUSB_ERROR_BUSY:
			sr_err("Unable to claim interface: already in use.");
			break;
		case LIBUSB_ERROR_NO_DEVICE:
			sr_err("Device has been disconnected.");
			break;
		default:
			sr_err("Unable to claim interface: %s.",
			       libusb_error_name(ret));
			break;
		}
		libusb_close(usb->devhdl);
		usb->devhdl = NULL;
		return SR_ERR;
	}

	devc->usb_ctx = drvc->sr_ctx->libusb_ctx;

	/* Restore this device's persisted settings, if any. */
	vllogic_conf_load(sdi);

	/* Probe is per session: forget any value from a previous run. */
	devc->measured_bps = 0;
	devc->bw_measured = FALSE;
	{
		const char *e = getenv("VLLOGIC_STRICT");

		/* Unset or "1" is strict; only an explicit "0" is permissive. */
		devc->strict = !(e && e[0] == '0' && e[1] == '\0');
	}

	return SR_OK;
}

static void vllogic_begin_stop(const struct sr_dev_inst *sdi);
static void vllogic_finish(const struct sr_dev_inst *sdi);

static int dev_close(struct sr_dev_inst *sdi)
{
	struct sr_usb_dev_inst *usb = sdi->conn;
	struct dev_context *devc = sdi->priv;

	/* Closing an already closed device is a no-op, not a bug. */
	if (!usb || !usb->devhdl)
		return SR_OK;

	if (devc && devc->rx) {
		sr_info("dev_close: state=%d, starting capture teardown.",
			devc->state);
		/*
		 * A close during a running capture must produce the same
		 * teardown as a normal stop: STOP, drain the queue, join the
		 * USB/parser threads, flush the tail and send SR_DF_END once.
		 *
		 * The teardown itself runs on the session thread (the timer
		 * source calls vllogic_finish()) so that no datafeed packet is
		 * ever emitted from this thread.  Wait for it, and only force
		 * the teardown if no session loop is running.
		 */
		if (atomic_load_explicit(&devc->state, memory_order_relaxed) == VLLOGIC_CAPTURING)
			vllogic_begin_stop(sdi);
		sr_info("dev_close: stop requested, state=%d, waiting.",
			devc->state);

		if (atomic_load_explicit(&devc->state, memory_order_relaxed) != VLLOGIC_IDLE) {
			int64_t deadline = g_get_monotonic_time() +
				5 * G_TIME_SPAN_SECOND;

			while (atomic_load_explicit(&devc->state, memory_order_relaxed) != VLLOGIC_IDLE &&
			       g_get_monotonic_time() < deadline)
				g_usleep(1000);
			sr_info("dev_close: wait finished, state=%d.",
				devc->state);
			if (atomic_load_explicit(&devc->state, memory_order_relaxed) != VLLOGIC_IDLE) {
				/*
				 * The session loop is gone, so no datafeed packet
				 * may be produced here (that would race with the
				 * timer source and can double-send END).
				 * Abandon the pipeline instead: stop the threads,
				 * drop the queue and let receive_data() return
				 * FALSE so the timer source is removed.
				 */
				sr_warn("Capture did not finish within 5 s; "
					"abandoning the receive pipeline from "
					"dev_close() (no datafeed emitted).");
				if (devc->rx) {
					vllogic_rx_set_stopping(devc->rx);
					vllogic_rx_stop(devc->rx);
					vllogic_rx_free(devc->rx);
					devc->rx = NULL;
				}
				atomic_store_explicit(&devc->state, VLLOGIC_IDLE,
						memory_order_release);
				if (sdi->session)
					sr_session_source_remove(sdi->session, -1);
			}
		}
	} else if (devc && atomic_load_explicit(&devc->state, memory_order_relaxed) != VLLOGIC_IDLE) {
		atomic_store_explicit(&devc->state, VLLOGIC_IDLE, memory_order_relaxed);
	}

	libusb_release_interface(usb->devhdl, VLLOGIC_IFACE);
	libusb_close(usb->devhdl);
	usb->devhdl = NULL;

	return SR_OK;
}

static void clear_private(void *priv)
{
	struct dev_context *devc = priv;

	if (!devc)
		return;
	if (devc->rx) {
		vllogic_rx_free(devc->rx);
		devc->rx = NULL;
	}
	/*
	 * devc itself is released by std_dev_clear_with_callback(), which
	 * calls g_free(sdi->priv) right after this callback returns.
	 */
}

static int dev_clear(const struct sr_dev_driver *di)
{
	return std_dev_clear_with_callback(di, clear_private);
}

/* ------------------------------------------------------------------------- */
/* Configuration                                                             */
/* ------------------------------------------------------------------------- */

static int config_get(uint32_t key, GVariant **data,
		const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;

	(void)cg;

	if (!sdi || !sdi->priv)
		return SR_ERR_ARG;

	devc = sdi->priv;

	switch (key) {
	case SR_CONF_SAMPLERATE:
		*data = g_variant_new_uint64(devc->samplerate);
		break;
	case SR_CONF_LIMIT_SAMPLES:
		*data = g_variant_new_uint64(devc->limit_samples);
		break;
	case SR_CONF_VOLTAGE_THRESHOLD:
		/*
		 * Return the nominal grid value last set, not the PWM-quantised
		 * voltage.  GUIs (PulseView prop/enum.cpp) locate the current
		 * entry by exact comparison against the LIST values, so GET and
		 * LIST must produce bit-identical doubles.
		 */
		*data = std_gvar_tuple_double(devc->cur_threshold,
				devc->cur_threshold);
		break;
	case SR_CONF_CONN:
		if (!sdi->connection_id)
			return SR_ERR_ARG;
		*data = g_variant_new_string(sdi->connection_id);
		break;
	default:
		return SR_ERR_NA;
	}

	if (key == SR_CONF_SAMPLERATE || key == SR_CONF_LIMIT_SAMPLES ||
	    key == SR_CONF_VOLTAGE_THRESHOLD)
		vllogic_conf_save((struct sr_dev_inst *)sdi);

	return SR_OK;
}

static int config_set(uint32_t key, GVariant *data,
		const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	struct dev_context *devc;

	(void)cg;

	if (!sdi || !sdi->priv)
		return SR_ERR_ARG;

	devc = sdi->priv;

	switch (key) {
	case SR_CONF_SAMPLERATE: {
		uint64_t rate = g_variant_get_uint64(data);
		const struct vllogic_rate *entry = NULL;
		size_t i;

		/*
		 * Only exact, supported rates are accepted.  Silently clamping
		 * (e.g. 1 MHz -> 20 MHz) hides a completely different capture.
		 */
		for (i = 0; i < VLLOGIC_NUM_RATES; i++) {
			if (vllogic_rates[i].rate == rate) {
				entry = &vllogic_rates[i];
				break;
			}
		}
		if (!entry) {
			sr_err("Unsupported samplerate %" PRIu64 " Hz; see "
				"SR_CONF_SAMPLERATE list.", rate);
			return SR_ERR_ARG;
		}
		if (atomic_load_explicit(&devc->state, memory_order_relaxed) != VLLOGIC_IDLE)
			return SR_ERR;
		devc->div = entry->div;
		devc->decimate = entry->decimate;
		devc->samplerate = entry->rate;
		break;
	}
	case SR_CONF_LIMIT_SAMPLES:
		if (atomic_load_explicit(&devc->state, memory_order_relaxed) != VLLOGIC_IDLE)
			return SR_ERR;
		devc->limit_samples = g_variant_get_uint64(data);
		break;
	case SR_CONF_VOLTAGE_THRESHOLD: {
		double low, high, vth;
		uint8_t pwm0, pwm1;

		if (!g_variant_is_of_type(data, G_VARIANT_TYPE("(dd)")))
			return SR_ERR_ARG;
		g_variant_get(data, "(dd)", &low, &high);
		vth = (low + high) / 2.0;

		/*
		 * The comparator covers -2.5 V .. +5.0 V.  Reject out-of-range
		 * values instead of clamping: a silently different threshold
		 * makes every captured level suspect.
		 */
		if (!isfinite(vth) || vth < -2.5 || vth > 5.0) {
			sr_err("Threshold %.3f V is outside -2.5 .. +5.0 V.",
				vth);
			return SR_ERR_ARG;
		}
		/*
		 * Quantise to the same 0.05 V grid the LIST advertises so the
		 * value reported by GET is bit-identical to a LIST entry.
		 */
		{
			long idx = lround((vth + 2.5) / 0.05);

			if (idx < 0)
				idx = 0;
			if (idx > 150)
				idx = 150;
			vth = -2.5 + (double)idx * 0.05;
		}
		if (vllogic_vth_to_pwm(vth, &pwm0, &pwm1) != 0) {
			sr_err("Threshold %.3f V cannot be represented.", vth);
			return SR_ERR_ARG;
		}

		/*
		 * The RTL accepts VBIAS changes while sampling (0x30/0x31).
		 * Send them without waiting for an ACK: the ACK would be
		 * consumed by the capture path.
		 */
		if (atomic_load_explicit(&devc->state, memory_order_relaxed) != VLLOGIC_IDLE && devc->rx) {
			if (vllogic_send_simple(devc->rx,
						UHSIF_CMD_VBIAS_PWM0, pwm0) !=
			    SR_OK ||
			    vllogic_send_simple(devc->rx,
						UHSIF_CMD_VBIAS_PWM1, pwm1) !=
			    SR_OK) {
				sr_err("Failed to apply the threshold while "
					"capturing.");
				return SR_ERR;
			}
		}

		devc->pwm0 = pwm0;
		devc->pwm1 = pwm1;
		devc->cur_threshold = vth;
		break;
	}
	default:
		return SR_ERR_NA;
	}

	if (key == SR_CONF_SAMPLERATE || key == SR_CONF_LIMIT_SAMPLES ||
	    key == SR_CONF_VOLTAGE_THRESHOLD)
		vllogic_conf_save((struct sr_dev_inst *)sdi);

	return SR_OK;
}

static int config_channel_set(const struct sr_dev_inst *sdi,
		struct sr_channel *ch, unsigned int changes)
{
	(void)ch;

	if (sdi && (changes & SR_CHANNEL_SET_ENABLED))
		vllogic_conf_save((struct sr_dev_inst *)sdi);

	return SR_OK;
}

static int config_list(uint32_t key, GVariant **data,
		const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	switch (key) {
	case SR_CONF_SAMPLERATE:
		*data = std_gvar_samplerates(vllogic_samplerates(),
				VLLOGIC_NUM_RATES);
		break;
	case SR_CONF_VOLTAGE_THRESHOLD: {
		/*
		 * 0.05 V grid, -2.5 .. +5.0 V (151 entries).  Built with the
		 * same expression as config_set() so GET == LIST exactly;
		 * std_gvar_min_max_step_thresholds() accumulates d += step and
		 * would not match bit-for-bit.
		 */
		GVariantBuilder *b = g_variant_builder_new(
				G_VARIANT_TYPE_ARRAY);
		int i;

		for (i = 0; i <= 150; i++) {
			double v = -2.5 + (double)i * 0.05;

			g_variant_builder_add(b, "(dd)", v, v);
		}
		*data = g_variant_builder_end(b);
		g_variant_builder_unref(b);
		break;
	}
	default:
		return STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts,
				devopts);
	}

	return SR_OK;
}

/* ------------------------------------------------------------------------- */
/* Acquisition                                                               */
/* ------------------------------------------------------------------------- */

static void vllogic_begin_stop(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

	if (!devc || devc->state != VLLOGIC_CAPTURING)
		return;

	/*
	 * STOP first, then stop resubmitting: a cancelled URB still carries
	 * the bytes received before the stop, and those belong to the
	 * capture window.
	 */
	if (devc->rx) {
		(void)vllogic_send_simple(devc->rx, UHSIF_CMD_STOP, 0);
		vllogic_rx_set_stopping(devc->rx);
	}

	atomic_store_explicit(&devc->state, VLLOGIC_STOPPING, memory_order_relaxed);
	devc->stop_deadline_us = g_get_monotonic_time() +
			(int64_t)VLLOGIC_DRAIN_MS * 1000;
}

static int vllogic_send_chunk(const struct sr_dev_inst *sdi,
		const uint8_t *data, size_t len)
{
	struct dev_context *devc = sdi->priv;
	struct sr_datafeed_packet packet;
	struct sr_datafeed_logic logic;

	logic.length = len;
	logic.unitsize = (uint16_t)devc->map.unitsize;
	logic.data = (void *)data;

	packet.type = SR_DF_LOGIC;
	packet.payload = &logic;

	if (sr_session_send(sdi, &packet) != SR_OK) {
		sr_err("Failed to send a %" G_GSIZE_FORMAT "-byte logic packet.",
			(gsize)len);
		return SR_ERR;
	}
	devc->samples_sent += len / (size_t)devc->map.unitsize;

	return SR_OK;
}

/* Drain queued chunks, up to a byte budget. */
static gsize vllogic_drain(const struct sr_dev_inst *sdi, gsize budget_max)
{
	struct dev_context *devc = sdi->priv;
	gsize budget = 0;

	while (devc->rx && budget < budget_max) {
		const uint8_t *data = NULL;
		size_t len = vllogic_rx_pop(devc->rx, &data);

		if (len == 0)
			break;
		if (vllogic_send_chunk(sdi, data, len) != SR_OK) {
			vllogic_rx_release(devc->rx);
			break;
		}
		budget += len;
		vllogic_rx_release(devc->rx);
	}

	return budget;
}

/* Tear everything down: only called from the session thread. */
static void vllogic_finish(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	struct uhsif_stats st;
	uint64_t dropped = 0;

	if (!devc->rx) {
		atomic_store_explicit(&devc->state, VLLOGIC_IDLE, memory_order_relaxed);
		return;
	}

	/* Cancel the remaining IN transfers, join both threads. */
	vllogic_rx_stop(devc->rx);

	/* The parser is gone: everything it produced is now queued. */
	while (vllogic_drain(sdi, G_MAXSIZE) > 0)
		;

	vllogic_rx_get_stats(devc->rx, &st, &dropped);
	sr_info("Capture summary: blocks=%" G_GUINT64_FORMAT
		" data=%" G_GUINT64_FORMAT " acks=%" G_GUINT64_FORMAT
		" words=%" G_GUINT64_FORMAT " crc_fail=%" G_GUINT64_FORMAT
		" bad_len=%" G_GUINT64_FORMAT " seq_jumps=%" G_GUINT64_FORMAT
		" drop_blocks=%" G_GUINT64_FORMAT " junk=%" G_GUINT64_FORMAT
		" mask_mismatch=%" G_GUINT64_FORMAT
		" partial=%" G_GUINT64_FORMAT " dropped=%" G_GUINT64_FORMAT
		" sink_short=%" G_GUINT64_FORMAT,
		st.blocks, st.data_blocks, st.acks, st.payload_words,
		st.crc_fail, st.bad_len, st.seq_jumps, st.drop_blocks,
		st.junk_bytes, st.mask_mismatch, st.partial_snapshots, dropped,
		st.sink_short);

	/* END once, after both threads have been joined. */
	sr_info("Capture teardown complete, sending SR_DF_END.");
	(void)std_session_send_df_end(sdi);

	vllogic_rx_free(devc->rx);
	devc->rx = NULL;
	atomic_store_explicit(&devc->state, VLLOGIC_IDLE, memory_order_relaxed);
}

static int receive_data(int fd, int revents, void *cb_data)
{
	struct sr_dev_inst *sdi = cb_data;
	struct dev_context *devc = sdi->priv;

	(void)fd;
	(void)revents;

	if (!devc || !devc->rx)
		return FALSE;

	if (devc->rx) {
		uint64_t ev = vllogic_rx_drop_events(devc->rx);

		if (ev != devc->last_drop_events) {
			devc->last_drop_events = ev;
			sr_warn("Device drop_flag raised: the FPGA FIFO dropped "
				"at least one snapshot (%" G_GUINT64_FORMAT
				" event(s) so far).", ev);
		}
	}

	(void)vllogic_drain(sdi, VLLOGIC_SEND_BUDGET);

	if (atomic_load_explicit(&devc->state, memory_order_relaxed) == VLLOGIC_CAPTURING) {
		char msg[160];

		if (vllogic_rx_first_block_bad(devc->rx, msg, sizeof(msg))) {
			sr_err("%s", msg);
			vllogic_begin_stop(sdi);
		} else if (vllogic_rx_fatal(devc->rx)) {
			sr_err("USB transfer failed, stopping the capture.");
			vllogic_begin_stop(sdi);
		} else if (devc->limit_samples != 0 &&
			   (devc->samples_sent >= devc->limit_samples ||
			    vllogic_rx_samples_produced(devc->rx) >=
			    devc->limit_samples)) {
			vllogic_begin_stop(sdi);
		} else if (devc->start_us != 0 &&
			   g_get_monotonic_time() - devc->start_us >=
			   (int64_t)G_TIME_SPAN_SECOND &&
			   vllogic_rx_blocks(devc->rx) == 0) {
			sr_err("No CRC-valid block within 1000 ms of START; "
				"the device is not streaming.");
			vllogic_begin_stop(sdi);
		}
	} else if (atomic_load_explicit(&devc->state, memory_order_relaxed) == VLLOGIC_STOPPING) {
		if (g_get_monotonic_time() >= devc->stop_deadline_us) {
			vllogic_finish(sdi);
			/* Removes the timer source. */
			return FALSE;
		}
	}

	return TRUE;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;
	struct sr_channel *ch;
	GSList *l;
	int logical[VLLOGIC_NUM_CHANNELS];
	int nlogical = 0;
	int ret;

	if (atomic_load_explicit(&devc->state, memory_order_relaxed) != VLLOGIC_IDLE) {
		sr_err("Acquisition already running.");
		return SR_ERR;
	}

	for (l = sdi->channels; l; l = l->next) {
		ch = l->data;
		if (ch->type != SR_CHANNEL_LOGIC || !ch->enabled)
			continue;
		if (ch->index < 0 || ch->index >= VLLOGIC_NUM_CHANNELS)
			continue;
		logical[nlogical++] = ch->index;
	}
	if (nlogical == 0) {
		sr_err("No logic channels enabled.");
		return SR_ERR;
	}

	/*
	 * USB/FPGA bandwidth limit, see docs/总体设计.md:
	 *   >800M:2ch, >400M:4ch, >200M:8ch, >160M:16ch, <=160M:20ch.
	 * The FPGA silently drops snapshots when this is exceeded, so refuse
	 * the configuration instead of producing a corrupt capture.
	 */
	{
		int maxch = vllogic_max_channels(devc->samplerate);

		if (nlogical > maxch) {
			sr_err("Samplerate %" PRIu64 " Hz supports at most "
				"%d channels, but %d are enabled.",
				devc->samplerate, maxch, nlogical);
			return SR_ERR_ARG;
		}
	}

	if (vllogic_map_build(logical, nlogical, &devc->map) != 0) {
		sr_err("Invalid channel selection.");
		return SR_ERR;
	}

	devc->samples_sent = 0;
	devc->rx = vllogic_rx_new(sdi, &devc->map, devc->limit_samples);
	if (!devc->rx) {
		sr_err("Failed to allocate the receive pipeline.");
		return SR_ERR;
	}

	/*
	 * Link probe: once per session, before the event thread starts, so
	 * EP1 is owned exclusively.  Three 200 ms counter-mode bursts; take
	 * the median to reject a single noisy sample.
	 */
	if (!devc->bw_measured) {
		uint64_t v[3];
		int got = 0, i, j;

		for (i = 0; i < 3; i++) {
			uint64_t bps = 0;

			if (vllogic_probe_link(devc->rx, 200, &bps) == SR_OK &&
			    bps > 0)
				v[got++] = bps;
		}
		if (got > 0) {
			for (i = 0; i < got; i++)
				for (j = i + 1; j < got; j++)
					if (v[j] < v[i]) {
						uint64_t t = v[i];
						v[i] = v[j];
						v[j] = t;
					}
			devc->measured_bps = v[got / 2];
			devc->bw_measured = TRUE;
			sr_info("Link probe: %" PRIu64 " MB/s (sync, 200 ms, "
				"median of %d/3: %" PRIu64 "/%" PRIu64 "/%" PRIu64
				" MB/s; x1.10 calibration).",
				devc->measured_bps / 1000000, got,
				got > 0 ? v[0] / 1000000 : 0,
				got > 1 ? v[got / 2] / 1000000 : 0,
				got > 0 ? v[got - 1] / 1000000 : 0);
		} else {
			sr_warn("Link probe failed; using the static cap "
				"(400/35/5 MB/s by link speed).");
		}
	}

	/*
	 * Bandwidth admission: required = rate * nchan / 8.  The COUNTER
	 * probe under-reports the sustained EP1 rate by ~4% (it bypasses
	 * SerDes/bulk_buffer), so the measured value is scaled by 1.10 and
	 * then by the platform safety factor (0.98 on Linux, 0.85 on
	 * Windows).  The result is capped at the 400 MB/s sustained ceiling
	 * measured with 8ch@400MHz / 16ch@200MHz.  Strict mode refuses the
	 * configuration; permissive mode only warns.
	 */
	{
		struct sr_usb_dev_inst *usb = sdi->conn;
		uint64_t required = (VLLOGIC_CLOCK_HZ / devc->div) *
				(uint64_t)nlogical / 8u;
		uint64_t limit;
		const char *source;
		const char *env;
		double safety;

		if (devc->bw_measured) {
			/*
			 * The synchronous COUNTER probe under-reports the
			 * sustained EP1 rate.  Measured over 10 s (3 runs):
			 *
			 *   normal  8ch@400MHz : 400.4 MB/s   (peak observed)
			 *   normal 16ch@200MHz : 400.4 MB/s
			 *   normal 20ch@150MHz : 375.4 MB/s
			 *   normal 20ch@100MHz : 250.4 MB/s
			 *   counter 2ch@1200MHz: 384.9 MB/s
			 *   wave                 0 MB/s without a trigger edge
			 *
			 * Only COUNTER runs without input or a trigger edge, so it
			 * is the only mode usable for a start-up probe.  It is
			 * ~3.9% low because mode 0x06 bypasses the SerDes and
			 * bulk_buffer path and inserts ~2.2 us per 4092-word
			 * block; the real capture path reaches 400.4 MB/s.
			 *
			 * "420 MB/s" is NOT a measurement: it is la_recv's static
			 * LINK_LIMIT_BPS (401 MiB/s = 420.48 MB/s).  The highest
			 * sustained rate ever observed here is 400.4 MB/s, and
			 * 60 s / 30 s captures at 375 / 400 MB/s ran with zero
			 * drops, so the admitted ceiling is capped at 400 MB/s.
			 *
			 * calibration 1.10 covers the mode gap plus headroom;
			 * 0.98 safety keeps 400 MB/s admitted even when the probe
			 * reads low (378 * 1.10 * 0.98 = 407).
			 */
			const double calibration = 1.10;
			const double link_ceiling = 400.0 * 1000 * 1000;
#ifdef _WIN32
			safety = 0.85;
#else
			safety = 0.98;
#endif
			limit = (uint64_t)((double)devc->measured_bps *
					calibration * safety);
			if ((double)limit > link_ceiling)
				limit = (uint64_t)link_ceiling;
			source = "probe";
		} else {
			libusb_device *udev = (usb && usb->devhdl) ?
					libusb_get_device(usb->devhdl) : NULL;
			int speed = udev ? libusb_get_device_speed(udev) : -1;

			limit = 5ull * 1000 * 1000;
			if (speed == LIBUSB_SPEED_SUPER ||
			    speed == LIBUSB_SPEED_SUPER_PLUS)
				limit = 400ull * 1000 * 1000;
			else if (speed == LIBUSB_SPEED_HIGH)
				limit = 35ull * 1000 * 1000;
			source = "static";
		}

		env = getenv("VLLOGIC_MAX_MBPS");
		if (env && *env) {
			uint64_t override = strtoull(env, NULL, 10) *
					1000000ull;

			if (override > 0) {
				sr_warn("VLLOGIC_MAX_MBPS=%" PRIu64 " overrides "
					"the %s limit (%" PRIu64 " MB/s).",
					override / 1000000, source,
					limit / 1000000);
				limit = override;
				source = "env";
			}
		}

		if (required > limit) {
			char msg[256];

			g_snprintf(msg, sizeof(msg),
				"Capture needs %" PRIu64 " MB/s (%" PRIu64
				" Hz x %d ch) but the %s limit is %" PRIu64
				" MB/s (measured %" PRIu64 " MB/s); reduce the "
				"samplerate or the channel count.",
				required / 1000000, devc->samplerate, nlogical,
				source, limit / 1000000,
				devc->measured_bps / 1000000);
			if (devc->strict) {
				sr_err("%s", msg);
				goto err_free;
			}
			sr_warn("%s (VLLOGIC_STRICT=0: starting anyway, "
				"samples may be dropped).", msg);
		}
	}

	if (vllogic_config_device(devc->rx, devc) != SR_OK) {
		sr_err("Failed to configure the device.");
		goto err_free;
	}

	/* Arm the IN transfers (no data flows before START). */
	if (vllogic_rx_start(devc->rx) != SR_OK)
		goto err_free;

	/* The header must precede the first sample packet. */
	if (std_session_send_df_header(sdi) != SR_OK) {
		sr_err("Failed to send the datafeed header.");
		goto err_free;	/* no header went out, so no END either */
	}

	if (vllogic_send_simple(devc->rx, UHSIF_CMD_START, 0) != SR_OK) {
		sr_err("Failed to start the capture.");
		goto err_stop;
	}

	atomic_store_explicit(&devc->state, VLLOGIC_CAPTURING, memory_order_relaxed);
	devc->start_us = g_get_monotonic_time();

	/* Periodic source with a negative key: the fd slot is unused. */
	ret = sr_session_source_add(sdi->session, -1, 0, VLLOGIC_POLL_MS,
			receive_data, (void *)sdi);
	if (ret != SR_OK) {
		sr_err("Failed to add the session timer source.");
		(void)vllogic_send_simple(devc->rx, UHSIF_CMD_STOP, 0);
		goto err_stop;
	}

	sr_info("Acquisition started: %" G_GUINT64_FORMAT " Hz, %d channels, "
		"unitsize %d, div %u, decimate %u, threshold %.2f V, "
		"pwm0 %u, pwm1 %u.",
		devc->samplerate, devc->map.nchan, devc->map.unitsize,
		devc->div, devc->decimate, devc->cur_threshold,
		devc->pwm0, devc->pwm1);

	return SR_OK;

err_stop:
	if (devc->rx)
		(void)vllogic_send_simple(devc->rx, UHSIF_CMD_STOP, 0);
	/* The header already went out: close the stream exactly once. */
	(void)std_session_send_df_end(sdi);
err_free:
	/*
	 * Release the whole receive pipeline exactly once.  The old code
	 * only cleared devc->rx here, leaking 16 x 256 KiB URBs plus 256
	 * chunks (12 MiB) on every failed start.
	 */
	if (devc->rx) {
		vllogic_rx_free(devc->rx);
		devc->rx = NULL;
	}
	atomic_store_explicit(&devc->state, VLLOGIC_IDLE, memory_order_relaxed);
	devc->start_us = 0;

	return SR_ERR;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	struct dev_context *devc = sdi->priv;

	if (!devc || devc->state != VLLOGIC_CAPTURING)
		return SR_OK;

	/*
	 * Delayed stop: keep the timer source running so the tail of the
	 * capture can still be delivered to the session, cf. asix-sigma.
	 */
	vllogic_begin_stop(sdi);

	return SR_OK;
}

/* ------------------------------------------------------------------------- */
/* Driver registration                                                       */
/* ------------------------------------------------------------------------- */

static int init(struct sr_dev_driver *di, struct sr_context *sr_ctx)
{
	return std_init(di, sr_ctx);
}

static int cleanup(const struct sr_dev_driver *di)
{
	return std_cleanup(di);
}

static GSList *dev_list(const struct sr_dev_driver *di)
{
	return std_dev_list(di);
}

static struct sr_dev_driver vllogic_logic_driver_info = {
	.name = "vllogic-logic",
	.longname = "VLLogic Logic20",
	.api_version = 1,
	.init = init,
	.cleanup = cleanup,
	.scan = scan,
	.dev_list = dev_list,
	.dev_clear = dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_list = config_list,
	.config_channel_set = config_channel_set,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};

SR_REGISTER_DEV_DRIVER(vllogic_logic_driver_info);
