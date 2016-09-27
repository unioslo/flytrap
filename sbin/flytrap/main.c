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

#include <ft/endian.h>
#include <ft/ethernet.h>
#include <ft/ip4.h>
#include <ft/log.h>
#include <ft/pidfile.h>

#include "flytrap.h"
#include "ethernet.h"

static const char *ft_pidfile = "/var/run/flytrap.pid";
static int ft_foreground = 0;

ip4s_node *included;

static int
include_range(const char *range)
{
	ip4_addr first, last;

	if (ip4_parse_range(range, &first, &last) == NULL)
		return (-1);
	fprintf(stderr, "include %u.%u.%u.%u - %u.%u.%u.%u\n",
	    first.o[0], first.o[1], first.o[2], first.o[3],
	    last.o[0], last.o[1], last.o[2], last.o[3]);
	if (included == NULL)
		if ((included = ip4s_new()) == NULL)
			return (-1);
	if (ip4s_insert(included, be32toh(first.q), be32toh(last.q)) != 0)
		return (-1);
	return (0);
}

static int
exclude_range(const char *range)
{
	ip4_addr first, last;

	if (ip4_parse_range(range, &first, &last) == NULL)
		return (-1);
	fprintf(stderr, "exclude %u.%u.%u.%u - %u.%u.%u.%u\n",
	    first.o[0], first.o[1], first.o[2], first.o[3],
	    last.o[0], last.o[1], last.o[2], last.o[3]);
	if (included == NULL)
		if ((included = ip4s_new()) == NULL ||
		    ip4s_insert(included, 0U, ~0U) != 0)
			return (-1);
	if (ip4s_remove(included, be32toh(first.q), be32toh(last.q)) != 0)
		return (-1);
	return (0);
}

static void
daemonize(void)
{
	struct ft_pidfh *pidfh;
	pid_t pid;

	if ((pidfh = ft_pidfile_open(ft_pidfile, 0600, &pid)) == NULL) {
		if (errno == EEXIST) {
			ft_fatal("already running with PID %lu",
			    (unsigned long)pid);
		} else {
			ft_fatal("unable to open or create pidfile %s: %s",
			    ft_pidfile, strerror(errno));
		}
	}
	if (daemon(0, 0) != 0)
		ft_fatal("unable to daemonize: %s", strerror(errno));
	ft_pidfile_write(pidfh);
}

static void
usage(void)
{

	fprintf(stderr, "usage: flytrap [-dfnv] [-p pidfile] [-x addr] interface\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *ifname;
	int opt, ret;

	ifname = NULL;
	ft_log_level = FT_LOG_LEVEL_NOTICE;
	while ((opt = getopt(argc, argv, "dfhi:l:nvx:")) != -1) {
		switch (opt) {
		case 'd':
			if (ft_log_level > FT_LOG_LEVEL_DEBUG)
				ft_log_level = FT_LOG_LEVEL_DEBUG;
			break;
		case 'f':
			ft_foreground = 1;
			break;
		case 'i':
			if (include_range(optarg) != 0)
				usage();
			break;
		case 'l':
			ft_logname = optarg;
			break;
		case 'n':
			ft_dryrun = 1;
			break;
		case 'p':
			ft_pidfile = optarg;
			break;
		case 'v':
			if (ft_log_level > FT_LOG_LEVEL_VERBOSE)
				ft_log_level = FT_LOG_LEVEL_VERBOSE;
			break;
		case 'x':
			if (exclude_range(optarg) != 0)
				usage();
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();
	ifname = *argv;

	if (!ft_foreground)
		daemonize();

	ft_log_init("flytrap", NULL);
	ret = flytrap(ifname);
	ft_log_exit();

	exit(ret == 0 ? 0 : 1);
}
