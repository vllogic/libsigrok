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
 * Stand-alone self test for the vllogic-logic driver.
 *
 * It exercises exactly the code the driver runs at capture time but needs
 * neither hardware, libusb nor libsigrok.  Usage:
 *
 *   ./vllogic-selftest [--selftest] [--quiet]
 *
 * Exit status 0 means PASS.
 *
 * The two implementation files are pulled in as a single translation unit on
 * purpose: automake refuses to compile the same source path both into the
 * libtool driver library and into a plain test program ("object created both
 * with libtool and without"), and duplicating the parser would mean testing a
 * copy instead of the real thing.
 */

#include <stdio.h>
#include <string.h>

#include "protocol.c"
#include "uhsif_rx.c"

int main(int argc, char **argv)
{
	int verbose = 1;
	int ret;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--quiet") == 0)
			verbose = 0;
		else if (strcmp(argv[i], "--selftest") == 0)
			verbose = 1;
		else {
			fprintf(stderr, "usage: %s [--selftest] [--quiet]\n",
				argv[0]);
			return 2;
		}
	}

	printf("vllogic-logic built-in selftest (no hardware access)\n");
	ret = uhsif_selftest(verbose);
	printf("[vllogic-selftest] summary: %s\n", ret == 0 ? "PASS" : "FAIL");

	return ret;
}
