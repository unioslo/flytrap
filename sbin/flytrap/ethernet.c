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

#include <sys/types.h>
#include <sys/time.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ft/endian.h>
#include <ft/ethernet.h>
#include <ft/ip4.h>
#include <ft/log.h>

#include "flytrap.h"
#include "flow.h"
#include "iface.h"
#include "packet.h"

int
packet_analyze_ethernet(const packet *p, const void *data, size_t len)
{
	ether_flow fl;
	const ether_hdr *eh;
	int ret;

	if (len < sizeof(ether_hdr)) {
		ft_verbose("%d.%03d short Ethernet packet (%zd < %zd)",
		    p->ts.tv_sec, p->ts.tv_usec / 1000,
		    len, sizeof(ether_hdr));
		return (-1);
	}
	eh = data;
	data = eh + 1;
	len -= sizeof *eh;
	ft_debug("%d.%03d recv type %04x packet "
	    "from %02x:%02x:%02x:%02x:%02x:%02x "
	    "to %02x:%02x:%02x:%02x:%02x:%02x "
	    "len %zu",
	    p->ts.tv_sec, p->ts.tv_usec / 1000, be16toh(eh->type),
	    eh->src.o[0], eh->src.o[1], eh->src.o[2],
	    eh->src.o[3], eh->src.o[4], eh->src.o[5],
	    eh->dst.o[0], eh->dst.o[1], eh->dst.o[2],
	    eh->dst.o[3], eh->dst.o[4], eh->dst.o[5],
	    len);
	fl.p = p;
	fl.src = eh->src;
	fl.dst = eh->dst;
	fl.type = be16toh(eh->type);
	fl.len = len;
	switch (fl.type) {
	case ether_type_arp:
		ret = packet_analyze_arp(&fl, data, len);
		break;
	case ether_type_ip:
		ret = packet_analyze_ip4(&fl, data, len);
		break;
	default:
		ret = -1;
	}
	return (ret);
}

int
ethernet_send(iface *i, ether_type type, const ether_addr *dst,
    const void *data, size_t len)
{
	packet p;
	ether_hdr *eh;
	int ret;

	p.i = i;
	p.len = sizeof *eh + len;
	if ((eh = malloc(p.len)) == NULL)
		return (-1);
	p.data = eh;
	memcpy(&eh->dst, dst, sizeof eh->dst);
	memcpy(&eh->src, &i->ether, sizeof eh->src);
	eh->type = htobe16(type);
	memcpy(eh + 1, data, len);
	gettimeofday(&p.ts, NULL);
	ft_debug("%d.%03d send type %04x packet "
	    "from %02x:%02x:%02x:%02x:%02x:%02x "
	    "to %02x:%02x:%02x:%02x:%02x:%02x",
	    p.ts.tv_sec, p.ts.tv_usec / 1000, be16toh(eh->type),
	    eh->src.o[0], eh->src.o[1], eh->src.o[2],
	    eh->src.o[3], eh->src.o[4], eh->src.o[5],
	    eh->dst.o[0], eh->dst.o[1], eh->dst.o[2],
	    eh->dst.o[3], eh->dst.o[4], eh->dst.o[5]);
	ret = iface_transmit(&p);
	free(eh);
	if (ret != 0) {
		ft_warning("failed to send type %04x packet "
		    "to %02x:%02x:%02x:%02x:%02x:%02x",
		    eh->dst.o[0], eh->dst.o[1], eh->dst.o[2],
		    eh->dst.o[3], eh->dst.o[4], eh->dst.o[5]);
	}
	return (ret);
}

int
ethernet_reply(const ether_flow *fl, const void *data, size_t len)
{

	return (ethernet_send(fl->p->i, fl->type, &fl->src, data, len));
}

