/*
 * uciconfig.c
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

#include <stdlib.h>
#include <string.h>
#include <uci.h>

#include "dhcptester.h"

config_s *uc_initialize(config_s *cfg) {
        
        struct uci_context *ctx;
        struct uci_package *pkg;
        struct uci_ptr      ptr;
        char               *str;
        
        ctx = uci_alloc_context();
        if (cfg->config_path) {
                uci_set_confdir(ctx, cfg->config_path);
        }
        uci_load(ctx, "dhcptester", &pkg);

        #define read_config(section,option) \
        str = strdup("dhcptester.@" #section "[0]." #option); \
        if (uci_lookup_ptr(ctx, &ptr, str, true) == UCI_OK) { \
                cfg->section.option = strdup(ptr.o->v.string); \
        } \
        free(str);

        #define read_config_int(section,option) \
        str = strdup("dhcptester.@" #section "[0]." #option); \
        if (uci_lookup_ptr(ctx, &ptr, str, true) == UCI_OK) { \
                cfg->section.option = atoi(ptr.o->v.string); \
        } \
        free(str);

        read_config(capture,inputuri);
        read_config(capture,outputuri);
        read_config_int(capture,bytes);
        read_config_int(capture,maxfiles);

        uci_free_context(ctx);

        return cfg;

} /* uc_initialize() */

void uc_cleanup(config_s *cfg) {
	if (cfg->capture.inputuri)  { free(cfg->capture.inputuri); }
	if (cfg->capture.outputuri) { free(cfg->capture.outputuri); }
} /* uc_cleanup() */
