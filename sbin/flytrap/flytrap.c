/*-
 * Copyright (c) 2016-2017 Universitetet i Oslo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <ft/log.h>

#include "flytrap.h"

int ft_dryrun;

#ifndef FT_CSVFILE
#define FT_CSVFILE "/var/csv/flytrap.csv"
#endif

const char *ft_csvfile = FT_CSVFILE;

static sig_atomic_t sighup;

static void
signal_handler(int sig)
{

	switch (sig) {
	case SIGHUP:
		sighup++;
		break;
	}
}

int
flytrap(const char *iname)
{
	struct iface *i;
	struct packet *p;

	if (csv_open(ft_csvfile) != 0) {
		ft_error("failed to open CSV file: %s", strerror(errno));
		return (-1);
	}
	signal(SIGHUP, signal_handler); 
	if ((i = iface_open(iname)) == NULL)
		return (-1);
	if (iface_activate(i) != 0)
		goto fail;
	for (;;) {
		if (sighup) {
			sighup--;
			if (csv_open(ft_csvfile) != 0) {
				ft_warning("failed to reopen CSV file: %s",
				    strerror(errno));
			}
		}
		if ((p = iface_next(i)) == NULL) {
			if (errno == EAGAIN)
				continue;
			goto fail;
		}
		packet_analyze(p);
		packet_drop(p);
	}
	signal(SIGHUP, SIG_DFL);
	return (0);
fail:
	iface_close(i);
	return (-1);
}
