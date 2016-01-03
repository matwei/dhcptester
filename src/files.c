/*
 * rotate_backups.c
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
#include <stdlib.h>
#include <unistd.h>

#include "dhcptester.h"

char * make_path(const char *path, int num) {
	int n;
	int size = 100;
	char *p, *np;

	if (NULL == (p = malloc(size))) {
		return NULL;
	}
	while (1) {
		n = snprintf(p,size,"%s.%i",path,num);
		if (n < 0) {
			free(p);
			return NULL;
		}
		if (n < size) {
			return p;
		}
		size = n + 1;
		if (NULL == (np = realloc(p, size))) {
			free(p);
			return NULL;
		}
		else {
			p = np;
		}
	}
}

int_err_s rotate_backups(const char *path, int nbackups){
	int_err_s out = {};
	char *lp, *p;
	int i;
	if (0 == access(path,F_OK)) {
		if (NULL == (lp = make_path(path,nbackups))) {
			out.value = -1;
			out.error = "can't make path to rotate files";
			return out;
		}
		if (0 == access(lp,F_OK)) {
			unlink(lp);
		}
		for (i = nbackups;i > 1; i--) {
			if (NULL == (p = make_path(path,i-1))) {
				free(lp);
				out.value = -1;
				out.error = "can't make path to rotate files";
				return out;
			}
			if (0 == access(p,F_OK)) {
				rename(p,lp);
				out.value += 1;
			}
			free(lp);
			lp = p;
		}
		rename(path,lp);
		free(lp);
		out.value += 1;
	}
	return out;
}
