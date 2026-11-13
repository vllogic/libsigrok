/*
 * Worker-path variant of vllogic-selftest.
 *
 * selftest.c pulls in uhsif_rx.c as a single translation unit.  Defining
 * UHSIF_SELFTEST_MT before the include keeps the GLib worker code enabled,
 * while the plain vllogic-selftest target stays GLib-free.
 */
#define UHSIF_SELFTEST_MT 1
#include "selftest.c"
