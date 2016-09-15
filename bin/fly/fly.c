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

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ft/ctype.h>
#include <ft/endian.h>
#include <ft/log.h>

#define FLY_DEFAULT_PORT 80
static const char data[] = "GET / HTTP/0.9\r\n\r\n";

/*
 * Parse ip[:port].  This belongs in a library somewhere.
 */
static int
parse_ip_port(const char *str, struct sockaddr_in *sin4)
{
	unsigned int addr[4] = { 0, 0, 0, 0 };
	unsigned int port = 0;
	int i, p;

	for (i = p = 0; i < 4; ++i) {
		if (i > 0 && str[p++] != '.')
			return (-1);
		while (is_digit(str[p])) {
			addr[i] = addr[i] * 10 + str[p++] - '0';
			if (addr[i] > 255)
				return (-1);
		}
	}
	if (str[p] == ':') {
		p++;
		while (is_digit(str[p])) {
			port = port * 10 + str[p++] - '0';
			if (port > 65535)
				return (-1);
		}
		if (port == 0)
			return (-1);
	}
	if (str[p] != '\0')
		return (-1);
	if (port == 0)
		port = FLY_DEFAULT_PORT;
	memset(sin4, 0, sizeof *sin4);
#if HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sin4->sin_len = sizeof *sin4;
#endif
	sin4->sin_family = AF_INET;
	sin4->sin_port = htobe16(port);
	sin4->sin_addr.s_addr =
	    htobe32(addr[0] << 24 | addr[1] << 16 | addr[2] << 8 | addr[3]);
	return (0);
}

static int
fly(const char *target, int linger, int timeout)
{
	struct sockaddr_in sin4;
	struct timeval tv;
	struct linger l;
	ssize_t sent;
	int sd;

	if (parse_ip_port(target, &sin4) != 0) {
		ft_error("invalid ip[:port] specification");
		return (-1);
	}
	if ((sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		ft_error("socket(): %s", strerror(errno));
		return (-1);
	}
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) != 0) {
		ft_error("setsockopt(SO_SNDTIMEO): %s", strerror(errno));
		close(sd);
		return (-1);
	}
	if (linger) {
		l.l_onoff = 1;
		l.l_linger = timeout;
		if (setsockopt(sd, SOL_SOCKET, SO_LINGER, &l, sizeof l) != 0) {
			ft_error("setsockopt(SO_LINGER): %s", strerror(errno));
			close(sd);
			return (-1);
		}
	}
	ft_verbose("attempting to connect to %s", target);
	if (connect(sd, (struct sockaddr *)&sin4, sizeof sin4) != 0) {
		ft_error("connect(): %s", strerror(errno));
		close(sd);
		return (-1);
	}
	ft_verbose("sending %zu bytes to %s", sizeof data - 1, target);
	if ((sent = write(sd, data, sizeof data - 1)) < 0) {
		if (errno == EWOULDBLOCK) {
			ft_warning("timed out while sending");
		} else {
			ft_error("write(): %s", strerror(errno));
			close(sd);
			return (-1);
		}
	} else if (sent > 0) {
		ft_warning("successfully sent %zd bytes", sent);
	}
	ft_verbose("closing connection");
	if (close(sd) != 0) {
		ft_error("close(): %s", strerror(errno));
		return (-1);
	}
	ft_verbose("connection closed");
	return (0);
}

static void
usage(void)
{

	fprintf(stderr, "usage: fly [-dlv] ip[:port]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int linger = 0, timeout = 10;
	int opt, ret;

	while ((opt = getopt(argc, argv, "dlv")) != -1)
		switch (opt) {
		case 'd':
			if (ft_log_level > FT_LOG_LEVEL_DEBUG)
				ft_log_level = FT_LOG_LEVEL_DEBUG;
			break;
		case 'l':
			linger = 1;
			break;
		case 'v':
			if (ft_log_level > FT_LOG_LEVEL_VERBOSE)
				ft_log_level = FT_LOG_LEVEL_VERBOSE;
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	ft_log_init("fly", NULL);
	ret = fly(*argv, linger, timeout);
	ft_log_exit();

	exit(ret == 0 ? 0 : 1);
}
