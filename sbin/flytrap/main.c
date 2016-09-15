/*-
 * Copyright (c) 2016 Universitetet i Oslo
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ft/log.h>
#include <ft/pidfile.h>

#include "flycatcher.h"
#include "ethernet.h"

static const char *fc_pidfile = "/var/run/flycatcher.pid";
static int fc_foreground = 0;

static int
exclude(const char *dqs)
{
	ipv4_addr addr;
	char *e;

	if ((e = ipv4_fromstr(dqs, &addr)) == NULL || *e != '\0')
		return (-1);
	return (arp_reserve(&addr));
}

static void
daemonize(void)
{
	struct fc_pidfh *pidfh;
	pid_t pid;

	if ((pidfh = fc_pidfile_open(fc_pidfile, 0600, &pid)) == NULL) {
		if (errno == EEXIST) {
			fc_fatal("already running with PID %lu",
			    (unsigned long)pid);
		} else {
			fc_fatal("unable to open or create pidfile %s: %s",
			    fc_pidfile, strerror(errno));
		}
	}
	if (daemon(0, 0) != 0)
		fc_fatal("unable to daemonize: %s", strerror(errno));
	fc_pidfile_write(pidfh);
}

static void
usage(void)
{

	fprintf(stderr, "usage: flycatcher [-dfnv] [-p pidfile] [-x addr] -i interface\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *ifname;
	int opt, ret;

	ifname = NULL;
	fc_log_level = FC_LOG_LEVEL_NOTICE;
	while ((opt = getopt(argc, argv, "dfhi:l:nvx:")) != -1) {
		switch (opt) {
		case 'd':
			if (fc_log_level > FC_LOG_LEVEL_DEBUG)
				fc_log_level = FC_LOG_LEVEL_DEBUG;
			break;
		case 'f':
			fc_foreground = 1;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'l':
			fc_logname = optarg;
			break;
		case 'n':
			fc_dryrun = 1;
			break;
		case 'p':
			fc_pidfile = optarg;
			break;
		case 'v':
			if (fc_log_level > FC_LOG_LEVEL_VERBOSE)
				fc_log_level = FC_LOG_LEVEL_VERBOSE;
			break;
		case 'x':
			if (exclude(optarg) != 0)
				usage();
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 0)
		usage();
	if (ifname == NULL)
		usage();

	if (!fc_foreground)
		daemonize();

	fc_log_init("flycatcher", NULL);
	ret = flycatcher(ifname);
	fc_log_exit();

	exit(ret == 0 ? 0 : 1);
}
