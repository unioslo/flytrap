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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <fc/assert.h>
#include <fc/ctype.h>
#include <fc/endian.h>
#include <fc/log.h>

#include "flycatcher.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

/*
 * Analyze a captured IP packet
 */
int
packet_analyze_ip4(struct packet *p, const void *data, size_t len)
{
	struct ipv4_flow fl;
	const ipv4_hdr *ih;
	size_t ihl;
	int ret;

	if (len < sizeof(ipv4_hdr)) {
		fc_notice("%d.%03d short IP packet (%zd < %zd)",
		    p->ts.tv_sec, p->ts.tv_usec / 1000,
		    len, sizeof(ipv4_hdr));
		return (-1);
	}
	ih = data;
	ihl = ipv4_hdr_ihl(ih) * 4;
	if (ihl < 20 || len < ihl || len != be16toh(ih->len)) {
		fc_notice("%d.%03d malformed IP header (plen %zd len %zd ihl %zd)",
		    p->ts.tv_sec, p->ts.tv_usec / 1000,
		    len, be16toh(ih->len), ihl);
		return (-1);
	}
	data = (const uint8_t *)data + ihl;
	len -= ihl;
	fc_debug("\tIP version %d proto %d from %d.%d.%d.%d to %d.%d.%d.%d",
	    ipv4_hdr_ver(ih), ih->proto,
	    ih->srcip.o[0], ih->srcip.o[1], ih->srcip.o[2], ih->srcip.o[3],
	    ih->dstip.o[0], ih->dstip.o[1], ih->dstip.o[2], ih->dstip.o[3]);
	fl.p = p;
	fl.src = ih->srcip;
	fl.dst = ih->dstip;
	switch (ih->proto) {
	case ip_proto_icmp:
		ret = packet_analyze_icmp4(&fl, data, len);
		break;
	case ip_proto_tcp:
		ret = packet_analyze_tcp4(&fl, data, len);
		break;
	case ip_proto_udp:
		ret = packet_analyze_udp4(&fl, data, len);
		break;
	default:
		ret = -1;
	}
	return (ret);
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

uint16_t
ip_cksum(uint16_t isum, const void *data, size_t len)
{
	const uint16_t *w;
	uint32_t sum;

	for (w = data, len /= 2, sum = isum; len > 0; --len, ++w)
		sum += be16toh(*w);
	while (sum > 0xffff)
		sum -= 0xffff;
	return (sum);
}

int
ipv4_reply(const struct ipv4_flow *fl, ip_proto proto,
    const void *data, size_t len)
{
	ether_addr ether;
	ipv4_hdr *ih;
	size_t iplen;
	int ret;

	if (arp_find(&fl->src, &ether) != 0) {
		fc_notice("ARP lookup failed: %d.%d.%d.%d",
		    fl->src.o[0], fl->src.o[1], fl->src.o[2], fl->src.o[3]);
		return (-1);
	}
	iplen = sizeof *ih + len;
	if ((ih = calloc(1, iplen)) == NULL)
		return (-1);
	ih->ver_ihl = 0x45;
	ih->dscp_ecn = 0x00;
	ih->len = htobe16(iplen);
	ih->id = 0x0000;
	ih->fl_off = 0x0000;
	ih->ttl = 0x40;
	ih->proto = proto;
	ih->srcip = fl->dst;
	ih->dstip = fl->src;
	ih->sum = htobe16(~ip_cksum(0, ih, sizeof *ih));
	memcpy(ih + 1, data, len);
	ret = ethernet_send(fl->p->i, ether_type_ip, &ether,
	    ih, iplen);
	free(ih);
	return (ret);
}
