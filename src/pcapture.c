/*
 * pcapture.c
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

#include <stdio.h>

#include <libtrace.h>

#include "dhcptester.h"

static char * bpf =
"( udp and ( port 67 or port 68 ) )"
	" or arp"
	" or ( icmp and (icmp[icmptype] == 8 or icmp[icmptype] == 0 ) )"
	" or ( udp and ( port 546 or port 547 ) )"
	" or ( icmp6 and ( ip6[40] == 135 or ip6[40] == 136 ) )"
	" or dst net ff02:0:0:0:0:1:ff00::/104"
	" or dst host ff01::1"
	" or dst host ff02::1"
	" or dst host ff02::1:2"
	" or ( icmp6 and ( ip6[40] == 128 or ip6[40] == 129 ) )";


void pcapture_cleanup(pcapture_s pcap) {
	if (pcap.trace)  trace_destroy(pcap.trace);
	if (pcap.output) trace_destroy_output(pcap.output);
	if (pcap.packet) trace_destroy_packet(pcap.packet);
	if (pcap.filter) trace_destroy_filter(pcap.filter);
}

int pcapture_read_packet(pcapture_s pcap) {

	return trace_read_packet(pcap.trace, pcap.packet);
}

pcapture_s pcapture_write_packet(pcapture_s pcap) {
	int ret;

	/*
	ret = trace_apply_filter(pcap.filter, pcap.packet);
	if (-1 == ret) {
		pcap.error = "Error applying filter";
		return pcap;
	}
	if (0 == ret) {
		return pcap;
	}
	*/
	uint64_t totbytes = pcap.totbytes;
	totbytes += trace_get_capture_length(pcap.packet);
	if (pcap.output && totbytes - pcap.totbyteslast > pcap.bytes) {
		trace_destroy_output(pcap.output);
		pcap.output=NULL;
		pcap.totbyteslast=pcap.totbytes;
		rotate_backups(pcap.outputfname,pcap.maxfiles - 1);
		/* TODO: check return */
	}
	if (! pcap.output) {
		pcap.output = trace_create_output(pcap.outputuri);
		if (trace_is_err_output(pcap.output)) {
			pcap.error = "Opening output trace file";
			return pcap;
		}
		if (-1 == trace_start_output(pcap.output)) {
			pcap.error = "Starting output trace";
		}
	}

	if (-1 == trace_write_packet(pcap.output, pcap.packet)) {
		pcap.error = "Writing packet";
	}
	pcap.totbytes = totbytes;
	return pcap;
}

char * makefname(char * uri) {
	char * p;
	if (NULL != uri) {
		p = uri;
		while (*p) {
			if (':' == *p) {
				return ++p;
			}
			++p;
		}
	}
	return uri;
}

pcapture_s pcapture_setup(char *inputuri, char *outputuri,
	       	uint64_t bytes, uint64_t maxfiles ) {

	pcapture_s pcap = {
		.outputuri   = outputuri,
		.bytes       = bytes,
		.maxfiles    = maxfiles
	};

	pcap.outputfname = makefname(outputuri),
	pcap.packet = trace_create_packet();
	if (NULL == pcap.packet) {
		pcap.error = "Creating libtrace packet";
		return pcap;
	}

	pcap.trace = trace_create(inputuri);
	if (trace_is_err(pcap.trace)) {
		pcap.error = "Opening trace URI";
		return pcap;
	}

	pcap.filter = trace_create_filter(bpf);
	if (NULL == pcap.filter) {
		pcap.error = "Creating packet filter";
		return pcap;
	}
	if (-1 == trace_config(pcap.trace, TRACE_OPTION_FILTER, pcap.filter)) {
		pcap.error = "Configuring filter";
		return pcap;
	}
	if (-1 == trace_start(pcap.trace)) {
		pcap.error = "Starting trace";
		return pcap;
	}

	pcap.output = trace_create_output(outputuri);
	if (trace_is_err_output(pcap.output)) {
		pcap.error = "Opening output trace file";
		return pcap;
	}
	if (-1 == trace_start_output(pcap.output)) {
		pcap.error = "Starting output trace";
	}
	return pcap;
}

/* vim: set tw=78 */
