/*-
 * Copyright (c) 2016-2018 The University of Oslo
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ft/endian.h>
#include <ft/ip4.h>
#include <ft/log.h>

#define DSHIELD_RECIPIENT "reports@dshield.org"

static const char *sender;
static const char *recipient;

static unsigned long userid;
static ip4s_node *src_set;
static ip4s_node *dst_set;
static time_t fromdate;
static time_t todate;

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
	static char tstr[64];
	static time_t t;
	const char *proto;
	int ret;

	if (ftl->tv.tv_sec != t) {
		t = ftl->tv.tv_sec;
		strftime(tstr, sizeof tstr, "%Y-%m-%d %H:%M:%S %z",
		    localtime(&t));
	}
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
			ft_warning("%s: %m", fn);
			return (-1);
		}
	}

	/* read line by line */
	lno = 0;
	while ((fgets(line, sizeof line, f)) != NULL) {
		for (len = 0; line[len] != '\0' && line[len] != '\n'; ++len)
			/* nothing */ ;
		if (line[len] != '\n') {
			ft_warning("%s:%d: line too long", fn, lno + 1);
			continue;
		}
		lno++;
		line[len] = '\0';
		if (ftlogparse(&logent, line) != 0) {
			ft_warning("%s:%d: unparseable log entry", fn, lno);
			continue;
		}
		if (logent.tv.tv_sec < fromdate)
			continue;
		if (logent.tv.tv_sec > todate)
			continue;
		if (src_set != NULL &&
		    !ip4s_lookup(src_set, be32toh(logent.sa.q)))
			continue;
		if (dst_set != NULL &&
		    !ip4s_lookup(dst_set, be32toh(logent.da.q)))
			continue;
		if (ftlogprint(&logent) < 0) {
			ft_warning("%s:%d: failed to print entry", fn, lno);
			continue;
		}
	}

	/* error or just EOF? */
	if ((ret = ferror(f)) != 0)
		ft_warning("%s: %m", fn);

	/* close */
	if (f != stdin)
		fclose(f);

	return (ret ? -1 : 0);
}

static void
include_range(ip4s_node **set, const char *range)
{
	ip4_addr first, last;

	if (ip4_parse_range(range, &first, &last) == NULL)
		ft_fatal("invalid address or range: %s", range);
	ft_verbose("include %u.%u.%u.%u - %u.%u.%u.%u",
	    first.o[0], first.o[1], first.o[2], first.o[3],
	    last.o[0], last.o[1], last.o[2], last.o[3]);
	if (*set == NULL) {
		if ((*set = ip4s_new()) == NULL)
			ft_fatal("ip4s_new(): %m");
	}
	if (ip4s_insert(*set, be32toh(first.q), be32toh(last.q)) != 0)
		ft_fatal("ip4s_insert(): %m");
}

static void
exclude_range(ip4s_node **set, const char *range)
{
	ip4_addr first, last;

	if (ip4_parse_range(range, &first, &last) == NULL)
		ft_fatal("invalid address or range: %s", range);
	ft_verbose("exclude %u.%u.%u.%u - %u.%u.%u.%u",
	    first.o[0], first.o[1], first.o[2], first.o[3],
	    last.o[0], last.o[1], last.o[2], last.o[3]);
	if (*set == NULL) {
		if ((*set = ip4s_new()) == NULL ||
		    ip4s_insert(*set, 0U, ~0U) != 0)
			ft_fatal("ip4s_new(): %m");
	}
	if (ip4s_remove(*set, be32toh(first.q), be32toh(last.q)) != 0)
		ft_fatal("ip4s_remove(): %m");
}

static time_t
parse_date(const char *date, int hilo)
{
	char tstr[64];
	struct tm tm, dt;
	time_t now, t;
	const char *e, *p;

	time(&now);
	p = date;
	t = (time_t)-1;
	memset(&dt, 0, sizeof dt);

	/* look for a date */
	if ((e = strptime(p, "%Y-%m-%d", &tm)) == NULL &&
	    (e = strptime(p, "%Y%m%d", &tm)) == NULL) {
		localtime_r(&now, &tm);
	} else {
		ft_debug("got date: %.*s => %04d-%02d-%02d", (int)(e - p), p,
		    1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday);
	}
	dt.tm_year = tm.tm_year;
	dt.tm_mon = tm.tm_mon;
	dt.tm_mday = tm.tm_mday;

	/* advance, possibly skipping a separator */
	if (e != NULL) {
		if (*e == 'T' || *e == ' ')
			e++;
		p = e;
	}

	/* look for a time */
	if ((e = strptime(p, "%H:%M:%S", &tm)) == NULL &&
	    (e = strptime(p, "%H%M%S", &tm)) == NULL) {
		tm.tm_hour = hilo > 0 ? 23 : 0;
		tm.tm_min = tm.tm_sec = hilo > 0 ? 59 : 0;
	} else {
		ft_debug("got time: %.*s => %02d:%02d:%02d", (int)(e - p), p,
		    tm.tm_hour, tm.tm_min, tm.tm_sec);
	}
	dt.tm_hour = tm.tm_hour;
	dt.tm_min = tm.tm_min;
	dt.tm_sec = tm.tm_sec;

	if (e != NULL)
		if (*(p = e) == 'Z')
			p++;

	/* did we reach the end of the string? */
	if (p == date || *p != '\0')
		ft_fatal("malformed date: %s", date);

	/* convert */
	dt.tm_isdst = -1;
	if (e != NULL && *e == 'Z')
		t = timegm(&dt);
	else
		t = mktime(&dt);
	if (t == (time_t)-1)
		ft_fatal("invalid date: %s", date);

	strftime(tstr, sizeof tstr, "%Y-%m-%d %H:%M:%S %z", &dt);
	ft_debug("got %lu => %s", (unsigned long)t, tstr);

	return (t);
}

static void
usage(void)
{

	fprintf(stderr, "usage: ft2dshield [-dhv] "
	    "[-o output] [-r recipient] [-s sender] [-u userid] "
	    "[-Ii addr|range|subnet] [-Xx addr|range|subnet] "
	    "[-f date] [-t date] [file ...]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *e;
	int i, opt;

	/* don't assume the signedness of time_t */
	fromdate = 0;
	todate = (time_t)-1;
	if (todate < fromdate)
		todate = (uintmax_t)todate >> 1;

	tzset();
	ft_log_init("ft2dshield", NULL);
	ft_log_level = FT_LOG_LEVEL_NOTICE;
	while ((opt = getopt(argc, argv, "df:hI:i:o:r:s:f:t:u:vX:x:")) != -1)
		switch (opt) {
		case 'd':
			if (ft_log_level > FT_LOG_LEVEL_DEBUG)
				ft_log_level = FT_LOG_LEVEL_DEBUG;
			break;
		case 'f':
			fromdate = parse_date(optarg, -1);
			break;
		case 'I':
			include_range(&src_set, optarg);
			break;
		case 'i':
			include_range(&dst_set, optarg);
			break;
		case 'o':
			if ((freopen(optarg, "a", stdout)) == NULL)
				ft_fatal("%s: %m", optarg);
			break;
		case 'r':
			recipient = optarg;
			break;
		case 's':
			sender = optarg;
			break;
		case 't':
			todate = parse_date(optarg, 1);
			break;
		case 'u':
			userid = strtoul(optarg, &e, 10);
			if (e == optarg || *e != '\0')
				usage();
			break;
		case 'v':
			if (ft_log_level > FT_LOG_LEVEL_VERBOSE)
				ft_log_level = FT_LOG_LEVEL_VERBOSE;
			break;
		case 'X':
			exclude_range(&src_set, optarg);
			break;
		case 'x':
			exclude_range(&dst_set, optarg);
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
