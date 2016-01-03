/** \file
 * signals.c
 * Copyright (C) 2015 Mathias Weidner <dhcptester@mamawe.net>
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

#include <signal.h>

/** makes it easier to write and read
 */
typedef void (*sighandler_t)(int);

/** counts, how many times SIGINT was catched while running the program
 */
static volatile sig_atomic_t sigint = 0;

/** the actual signal handler for SIGINT
 */
static void catch_sigint(int sig) {
	sigint++;
}

/** installs a signal handler and returns the old handler if there was
 *  any
 */
static sighandler_t add_handler(int sig_nr, sighandler_t handler) {
	struct sigaction newhandler, oldhandler;

	newhandler.sa_handler = handler;
	sigemptyset( &newhandler.sa_mask );
	newhandler.sa_flags = SA_RESTART;
	if (sigaction(sig_nr, &newhandler, &oldhandler) < 0) {
		return SIG_ERR;
	}
	return oldhandler.sa_handler;
}

/** activates all signal handlers
 */
void set_signal_handlers(void) {
	add_handler(SIGINT, catch_sigint);
}

/** get the status of the SIGINT signal handler
 *
 * The signal handler for SIGINT increases a counter whenever it catches
 * a SIGINT. This function returns the value of this counter.
 *
 * \return 0 == no SIGINT so far
 */
int get_sigint( void ) {
	return sigint;
}
