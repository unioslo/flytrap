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
#include <sys/time.h>

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <fc/assert.h>
#include <fc/ctype.h>
#include <fc/log.h>

#include "flycatcher.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

/*
 * Analyze a captured IP packet
 */
int
packet_analyze_ip(struct packet *p, const void *data, size_t len)
{
	const ip_hdr *ih;
	ipv4_addr srcip, dstip;

	(void)p;
	if (len < sizeof(ip_hdr)) {
		fc_notice("\tshort IP packet (%zd < %zd)", len, sizeof(ip_hdr));
		return (-1);
	}
	ih = data;
	memcpy(&srcip, &ih->srcip, sizeof(ipv4_addr));
	memcpy(&dstip, &ih->dstip, sizeof(ipv4_addr));
	fc_debug("\tIP version %d from %d.%d.%d.%d to %d.%d.%d.%d",
	    ip_hdr_ver(ih),
	    srcip.o[0], srcip.o[1], srcip.o[2], srcip.o[3],
	    dstip.o[0], dstip.o[1], dstip.o[2], dstip.o[3]);
	return (0);
}

/*
 * Convert dotted-quad to IPv4 address
 */
char *
ipv4_fromstr(const char *dqs, ipv4_addr *addr)
{
	unsigned long ul;
	const char *s;
	char *e;
	int i;

	s = dqs;
	for (s = dqs, i = 0; i < 4; ++i, s = e) {
		if ((i > 0 && *s++ != '.') || !is_digit(*s))
			return (NULL);
		ul = strtoul(s, &e, 10);
		if (e == s || ul > 255)
			return (NULL);
		addr->o[i] = ul;
	}
	return (e);
}
