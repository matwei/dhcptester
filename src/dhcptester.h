/*
 * dhcptester.h
 * Copyright (C) 2015 Mathias Weidner <mathias@mamawe.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <libtrace.h>

typedef struct {
	int     value;
	char const *error;
} int_err_s;

/* from signals.c */
void set_signal_handlers(void);
int get_sigint( void );

/* from pcapture.c */
typedef struct {
	libtrace_t *trace;
	libtrace_packet_t *packet;
	libtrace_out_t *output;
	libtrace_filter_t *filter;
	char const *error;
        char *outputuri;
	char *outputfname;
	uint64_t totbytes;         /* bytes written */
	uint64_t totbyteslast;     /* bytes written till last file */
	uint64_t bytes;
	uint64_t maxfiles;
} pcapture_s;

void pcapture_cleanup(pcapture_s);
int pcapture_read_packet(pcapture_s);
pcapture_s pcapture_setup(char *, char *, uint64_t, uint64_t);
pcapture_s pcapture_write_packet(pcapture_s);

/* from file.c */
int_err_s rotate_backups(const char *path, int nbackups);

/* for configuration */
typedef struct {
        struct {
                char *inputuri;
                char *outputuri;
		uint64_t bytes;
		uint64_t maxfiles;
        } capture;
        char * config_path;
} config_s;

/* from uciconfig.c */
config_s * uc_initialize(config_s *);
void       uc_cleanup(config_s *);

/* vim: set tw=78 */
