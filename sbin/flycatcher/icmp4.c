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
#include <fc/endian.h>
#include <fc/log.h>

#include "flycatcher.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

/*
 * Reply to an echo request
 */
static int
icmp4_reply(const ipv4_flow *fl, uint16_t id, uint16_t seq,
    const void *payload, size_t payloadlen)
{
	icmp_hdr *ih;
	size_t len;

	len = sizeof(icmp_hdr) + payloadlen;
	if ((ih = calloc(1, len)) == NULL)
		return (-1);
	ih->type = htobe16(icmp_type_echo_reply);
	ih->code = htobe16(0);
	ih->hdata = htobe32(id << 16 | seq);
	memcpy(ih->data, payload, payloadlen);
	ih->sum = htobe16(~ip_cksum(0, ih, len));
	fc_verbose("echo reply to %d.%d.%d.%d id 0x%04x seq 0x%04x",
	    fl->src.o[0], fl->src.o[1], fl->src.o[2], fl->src.o[3],
	    id, seq);
	ipv4_reply(fl, ip_proto_icmp, ih, len);
	free(ih);
	return (0);
}

/*
 * Analyze a captured ICMP packet
 */
int
packet_analyze_icmp4(const ipv4_flow *fl, const void *data, size_t len)
{
	const icmp_hdr *ih;
	uint16_t id, seq, sum;
	int ret;

	ih = data;
	if (len < sizeof *ih) {
		fc_notice("%d.%03d short ICMP packet (%zd < %zd)",
		    fl->p->ts.tv_sec, fl->p->ts.tv_usec / 1000,
		    len, sizeof *ih);
		return (-1);
	}
	if ((sum = ~ip_cksum(0, data, len)) != 0) {
		fc_notice("%d.%03d invalid ICMP checksum 0x%04hx",
		    fl->p->ts.tv_sec, fl->p->ts.tv_usec / 1000, sum);
		return (-1);
	}
	data = ih + 1;
	len -= sizeof *ih;
	switch (ih->type) {
	case icmp_type_echo_request:
		id = be32toh(ih->hdata) >> 16;
		seq = be32toh(ih->hdata) & 0xffff;
		fc_verbose("echo request from %d.%d.%d.%d id 0x%04x seq 0x%04x",
		    fl->src.o[0], fl->src.o[1], fl->src.o[2], fl->src.o[3],
		    id, seq);
		ret = icmp4_reply(fl, id, seq,
		    (const uint16_t *)ih->data, len);
		break;
	default:
		ret = 0;
	}
	log_packet4(&fl->p->ts, &fl->src, 0, &fl->dst, 0,
	    "ICMP", len, "%u.%u", ih->type, ih->code);
	return (ret);
}
