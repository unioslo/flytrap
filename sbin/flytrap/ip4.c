/*-
 * Copyright (c) 2016 The University of Oslo
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

#include <ft/assert.h>
#include <ft/ctype.h>
#include <ft/endian.h>
#include <ft/ethernet.h>
#include <ft/ip4.h>
#include <ft/log.h>

#include "flytrap.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

/*
 * Analyze a captured IP packet
 */
int
packet_analyze_ip4(ether_flow *ethfl, const void *data, size_t len)
{
	ip4_flow fl;
	const ip4_hdr *ih;
	size_t ihl;
	int ret;

	if (len < sizeof(ip4_hdr)) {
		ft_verbose("%d.%03d short IP packet (%zd < %zd)",
		    ethfl->p->ts.tv_sec, ethfl->p->ts.tv_usec / 1000,
		    len, sizeof(ip4_hdr));
		return (-1);
	}
	ih = data;
	ihl = ip4_hdr_ihl(ih) * 4;
	if (ihl < 20 || len < ihl || len < be16toh(ih->len)) {
		ft_verbose("%d.%03d malformed IP header "
		    "(plen %zd len %zd ihl %zd)",
		    ethfl->p->ts.tv_sec, ethfl->p->ts.tv_usec / 1000,
		    len, be16toh(ih->len), ihl);
		return (-1);
	}
	len = be16toh(ih->len);
	ft_debug("\tIP version %d proto %d len %zu"
	    " from %d.%d.%d.%d to %d.%d.%d.%d",
	    ip4_hdr_ver(ih), ih->proto, len,
	    ih->srcip.o[0], ih->srcip.o[1], ih->srcip.o[2], ih->srcip.o[3],
	    ih->dstip.o[0], ih->dstip.o[1], ih->dstip.o[2], ih->dstip.o[3]);
	if (src_set != NULL && !ip4s_lookup(src_set, be32toh(ih->srcip.q))) {
		ft_debug("\tsource address is out of bounds");
		return (0);
	}
	if (dst_set != NULL && !ip4s_lookup(dst_set, be32toh(ih->dstip.q))) {
		ft_debug("\tdestination address is out of bounds");
		return (0);
	}
	data = (const uint8_t *)data + ihl;
	len -= ihl;
	fl.eth = ethfl;
	fl.src = ih->srcip;
	fl.dst = ih->dstip;
	fl.proto = htobe16(ih->proto);
	fl.len = htobe16(len);
	ft_debug("0x%02x%02x 0x%02x%02x 0x%02x%02x"
	    " 0x%02x%02x 0x%02x%02x 0x%02x%02x",
	    fl.pseudo[0], fl.pseudo[1], fl.pseudo[2], fl.pseudo[3],
	    fl.pseudo[4], fl.pseudo[5], fl.pseudo[6], fl.pseudo[7],
	    fl.pseudo[8], fl.pseudo[9], fl.pseudo[10], fl.pseudo[11]);
	fl.sum = ip4_cksum(0, &fl.pseudo, sizeof fl.pseudo);
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

int
ip4_reply(ip4_flow *fl, ip_proto proto,
    const void *data, size_t len)
{
	ip4_hdr *ih;
	size_t iplen;
	int ret;

	ft_debug("ip4 proto %d to %02x:%02x:%02x:%02x:%02x:%02x", proto,
	    fl->eth->dst.o[0], fl->eth->dst.o[1], fl->eth->dst.o[2],
	    fl->eth->dst.o[3], fl->eth->dst.o[4], fl->eth->dst.o[5]);
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
	ih->sum = htobe16(~ip4_cksum(0, ih, sizeof *ih));
	memcpy(ih + 1, data, len);
	ret = ethernet_reply(fl->eth, ih, iplen);
	free(ih);
	return (ret);
}
