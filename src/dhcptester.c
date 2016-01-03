/*
 * dhcptester.c
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
#include <unistd.h>

#include "dhcptester.h"

char * bpf =
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


void libtrace_cleanup(libtrace_t *trace,
                      libtrace_out_t *output,
                      libtrace_packet_t * packet,
		      libtrace_filter_t * filter) {
	if (trace)  trace_destroy(trace);
	if (output) trace_destroy_output(output);
	if (packet) trace_destroy_packet(packet);
	if (filter) trace_destroy_filter(filter);
}

int per_packet(libtrace_out_t *output,
               libtrace_packet_t *packet,
	       libtrace_filter_t * filter) {
	int ret;

	ret = trace_apply_filter(filter, packet);
	if (-1 == ret) {
		fprintf(stderr,"Error applying filter\n");
		return -1;
	}
	if (0 == ret) {
		return 0;
	}

	if (-1 == trace_write_packet(output, packet)) {
		trace_perror_output(output, "Writing packet");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv) {

	int opt;
	config_s cfg = {
	       	.capture.bytes = UINT64_MAX,
	       	.capture.maxfiles = UINT64_MAX
       	};

	while ((opt = getopt(argc, argv, "c:")) != -1) {
		switch (opt) {
			case 'c':
				cfg.config_path = optarg;
				;;
		}
	}
	uc_initialize(&cfg);

	if (NULL == cfg.capture.inputuri) {
		fprintf(stderr, "Undefined inputuri in configuration\n");
		return 1;
	}
	if (NULL == cfg.capture.outputuri) {
		fprintf(stderr, "Undefined outputuri in configuration\n");
		return 1;
	}

	pcapture_s pcap;

	pcap = pcapture_setup(cfg.capture.inputuri,cfg.capture.outputuri,
			cfg.capture.bytes,cfg.capture.maxfiles);

	if (pcap.error) {
		fprintf(stderr, "Packet capture error (%s)\n", pcap.error);
		pcapture_cleanup(pcap);
		return 1;
	}

	set_signal_handlers();
	while (!get_sigint()) {
		if (0 >= pcapture_read_packet(pcap)) {
			pcapture_cleanup(pcap);
			return 0;
		}
		pcap = pcapture_write_packet(pcap);
		if (pcap.error) {
			fprintf(stderr, "Packet capture error (%s)\n", pcap.error);
			pcapture_cleanup(pcap);
			return 1;
		}
	}

	pcapture_cleanup(pcap);
	uc_cleanup(&cfg);
	return 0;
}

/* vim: set tw=78 */
