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

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ft/endian.h>
#include <ft/ip4.h>

#define DSHIELD_RECIPIENT "reports@dshield.org"

static const char *sender;
static const char *recipient;

static unsigned long userid;
static ip4s_node *included;

struct ftlog {
	struct timeval	 tv;
	ip4_addr	 sa;
	uint16_t	 sp;
	ip4_addr	 da;
	uint16_t	 dp;
	ip_proto	 proto;
	size_t		 len;
	char		 flags[10];
};

static int
ftlogparse(struct ftlog *ftl, const char *s)
{
	char *e, *f;
	long l;
	int i;

	memset(ftl, 0, sizeof *ftl);

	/* time (seconds) */
	ftl->tv.tv_sec = strtoul(s, &e, 10);
	if (e == s || *e != '.')
		return (-1);
	s = e + 1;

	/* time (microseconds) */
	ftl->tv.tv_usec = strtoul(s, &e, 10);
	if (e == s || *e != ',')
		return (-1);
	s = e + 1;

	/* source address (dotted quad) */
	for (i = 0; i < 4; ++i) {
		l = strtol(s, &e, 10);
		if (e == s || *e != (i == 3 ? ',' : '.') || l < 0 || l > 255)
			return (-1);
		ftl->sa.o[i] = l;
		s = e + 1;
	}

	/* source port */
	l = strtol(s, &e, 10);
	if (e == s || *e != ',' || l < 0 || l > 65535)
		return (-1);
	ftl->sp = l;
	s = e + 1;

	/* destination address (dotted quad) */
	for (i = 0; i < 4; ++i) {
		l = strtol(s, &e, 10);
		if (e == s || *e != (i == 3 ? ',' : '.') || l < 0 || l > 255)
			return (-1);
		ftl->da.o[i] = l;
		s = e + 1;
	}

	/* destination port */
	l = strtol(s, &e, 10);
	if (e == s || *e != ',' || l < 0 || l > 65535)
		return (-1);
	ftl->dp = l;
	s = e + 1;

	/* protocol */
	if ((e = strchr(s, ',')) == NULL)
		return (-1);
	if (e - s == 4 && strncmp(s, "ICMP", 4) == 0)
		ftl->proto = ip_proto_icmp;
	else if (e - s == 3 && strncmp(s, "TCP", 3) == 0)
		ftl->proto = ip_proto_tcp;
	else if (e - s == 3 && strncmp(s, "UDP", 3) == 0)
		ftl->proto = ip_proto_udp;
	else
		return (-1);
	s = e + 1;

	/* length */
	l = strtol(s, &e, 10);
	if (e == s || *e != ',' || l < 0 || l > 65535)
		return (-1);
	ftl->len = l;
	s = e + 1;

	/* additional */
	if (ftl->proto == ip_proto_icmp) {
		/* ICMP: store type in sp, code in dp */
		l = strtol(s, &e, 10);
		if (e == s || *e != '.' || l < 0 || l > 255)
			return (-1);
		ftl->sp = l;
		s = e + 1;
		l = strtol(s, &e, 10);
		if (e == s || *e != '\0' || l < 0 || l > 255)
			return (-1);
		ftl->dp = l;
		s = e;
	} else if (ftl->proto == ip_proto_tcp) {
		/* TCP: flags */
		for (i = 0, f = ftl->flags; i < 9; ++i) {
			switch (s[i]) {
			case 'S': case 'A': case 'F':
			case 'U': case 'R': case 'P':
				/* SYN, ACK, FIN, URG, RST, PSH */
				*f++ = s[i];
				break;
			case 'N': case 'C': case 'E':
				/* NS, CWR, ECE */
				break;
			case '-':
				/* unset */
				break;
			default:
				return (-1);
			}
		}
		s += i;
	} else if (ftl->proto == ip_proto_udp) {
		/* nothing */
	} else {
		/* impossiburu */
		return (-1);
	}
	if (*s != '\0')
		return (-1);
	return (0);
}

static int
ftlogprint(const struct ftlog *ftl)
{
	char tstr[64];
	const char *proto;
	struct tm *tm;
	time_t t;
	int ret;

	t = ftl->tv.tv_sec;
	tm = gmtime(&t);
	strftime(tstr, sizeof tstr, "%Y-%m-%d %H:%M:%S %z", tm);
	switch (ftl->proto) {
	case ip_proto_icmp:
		proto = "ICMP";
		break;
	case ip_proto_tcp:
		proto = "TCP";
		break;
	case ip_proto_udp:
		proto = "UDP";
		break;
	default:
		/* impossibiru */
		return (-1);
	}
	ret = printf("%s\t%lu\t%u\t%u.%u.%u.%u\t%u\t%u.%u.%u.%u\t%u\t%s\t%s\n",
	    tstr, userid, 1U,
	    ftl->sa.o[0], ftl->sa.o[1], ftl->sa.o[2], ftl->sa.o[3], ftl->sp,
	    ftl->da.o[0], ftl->da.o[1], ftl->da.o[2], ftl->da.o[3], ftl->dp,
	    proto, ftl->flags);
	return (ret);
}

static void
ft2header(void)
{
	char tstr[64];
	char *zstr;
	struct tm *tm;
	time_t t;

	time(&t);
	tm = gmtime(&t);
	strftime(tstr, sizeof tstr, "%d %b %Y %H:%M:%S %z", tm);
	zstr = strrchr(tstr, ' ') + 1;
	printf("Date: %s\n", tstr);
	printf("From: %s\n", sender);
	printf("To: %s\n", recipient);
	printf("Subject: FORMAT DSHIELD USERID %lu TZ %s %s %s\n",
	    userid, zstr, PACKAGE_NAME, PACKAGE_VERSION);
	printf("\n");
}

static int
ft2dshield(const char *fn)
{
	struct ftlog logent;
	FILE *f;
	char line[128];
	int len, lno, ret;

	/* open */
	if (fn == NULL) {
		fn = "stdin";
		f = stdin;
	} else {
		if ((f = fopen(fn, "r")) == NULL) {
			warn("%s", fn);
			return (-1);
		}
	}

	/* read line by line */
	lno = 0;
	while ((fgets(line, sizeof line, f)) != NULL) {
		for (len = 0; line[len] != '\0' && line[len] != '\n'; ++len)
			/* nothing */ ;
		if (line[len] != '\n') {
			warnx("%s:%d: line too long", fn, lno + 1);
			continue;
		}
		lno++;
		line[len] = '\0';
		if (ftlogparse(&logent, line) != 0) {
			warnx("%s:%d: unparseable log entry", fn, lno);
			continue;
		}
		if (included != NULL &&
		    !ip4s_lookup(included, be32toh(logent.sa.q)))
			continue;
		if (ftlogprint(&logent) < 0) {
			warnx("%s:%d: failed to print entry", fn, lno);
			continue;
		}
	}

	/* error or just EOF? */
	if ((ret = ferror(f)) != 0)
		warn("%s", fn);

	/* close */
	if (f != stdin)
		fclose(f);

	return (ret ? -1 : 0);
}

static void
include_range(const char *range)
{
	ip4_addr first, last;

	if (ip4_parse_range(range, &first, &last) == NULL)
		errx(1, "invalid address or range: %s", range);
	if (included == NULL) {
		if ((included = ip4s_new()) == NULL)
			err(1, "ip4s_new()");
	}
	if (ip4s_insert(included, be32toh(first.q), be32toh(last.q)) != 0)
		err(1, "ip4s_insert()");
}

static void
exclude_range(const char *range)
{
	ip4_addr first, last;

	if (ip4_parse_range(range, &first, &last) == NULL)
		errx(1, "invalid address or range: %s", range);
	if (included == NULL) {
		if ((included = ip4s_new()) == NULL)
			err(1, "ip4s_new()");
		if (ip4s_insert(included, 0U, ~0U) != 0)
			err(1, "ip4s_insert()");
	}
	if (ip4s_remove(included, be32toh(first.q), be32toh(last.q)) != 0)
		err(1, "ip4s_remove()");
}

static void
usage(void)
{

	fprintf(stderr, "usage: ft2dshield "
	    "[-h] [-i addr|range|subnet] [-o output] [-r recipient] "
	    "[-s sender] [-u userid] [-x addr|range|subnet] [file ...]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *e;
	int i, opt;

	while ((opt = getopt(argc, argv, "hi:o:r:s:u:x:")) != -1)
		switch (opt) {
		case 'i':
			include_range(optarg);
			break;
		case 'o':
			if ((freopen(optarg, "a", stdout)) == NULL)
				err(1, "%s", optarg);
			break;
		case 'r':
			recipient = optarg;
			break;
		case 's':
			sender = optarg;
			break;
		case 'u':
			userid = strtoul(optarg, &e, 10);
			if (e == optarg || *e != '\0')
				usage();
			break;
		case 'x':
			exclude_range(optarg);
			break;
		default:
			usage();
		}

	argc -= optind;
	argv += optind;

	/* check email-related options */
	if (recipient != NULL && sender == NULL)
		usage();
	if (sender != NULL && userid == 0)
		usage();

	/* print email header if requested */
	if (sender != NULL) {
		if (recipient == NULL)
			recipient = DSHIELD_RECIPIENT;
		ft2header();
	}

	/* iterate over input files */
	if (argc == 0)
		ft2dshield(NULL);
	else
		for (i = 0; i < argc; ++i)
			ft2dshield(argv[i]);

	/* done */
	exit(0);
}
