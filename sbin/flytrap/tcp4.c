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

#include <sys/time.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ft/endian.h>
#include <ft/ethernet.h>
#include <ft/ip4.h>
#include <ft/log.h>

#include "flytrap.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

/*
 * Log a TCP packet.
 */
static int
csv_tcp4(const struct timeval *ts, const ip4_addr *sa, const ip4_addr *da,
    const tcp4_hdr *th, size_t len)
{
	char flags[] = "NCEUAPRSF";
	unsigned int bit, mask;
	int ret;

	if (!tcp4_hdr_ns(th))
		flags[0] = '-';
	for (bit = 1, mask = 0x80; mask > 0; ++bit, mask >>= 1)
		if (!(th->fl & mask))
			flags[bit] = '-';
	ret = csv_packet4(ts, sa, be16toh(th->sp), da, be16toh(th->dp),
	    "TCP", len, flags);
	return (ret);
}

/*
 * Reply to a TCP packet with an RST.
 */
static int
tcp4_go_away(const ip4_flow *fl, const tcp4_hdr *ith, size_t ilen)
{
	tcp4_hdr oth;
	uint16_t olen, sum;
	int ret;

	(void)ilen;

	/* fill in header */
	oth.sp = ith->dp;
	oth.dp = ith->sp;
	oth.seq = htobe32(FLYTRAP_TCP4_SEQ);
	oth.ack = ith->seq;
	oth.off_ns = (sizeof oth / 4U) << 4;
	oth.fl = TCP4_RST;
	oth.win = htobe16(0);
	oth.sum = htobe16(0);
	oth.urg = htobe16(0);

	/* compute pseudo-header checksum, then packet checksum */
	sum = ip4_cksum(0, &fl->dst, sizeof fl->dst);
	sum = ip4_cksum(sum, &fl->src, sizeof fl->src);
	sum = ip4_cksum(sum, &fl->proto, sizeof fl->proto);
	olen = htobe16(sizeof oth);
	sum = ip4_cksum(sum, &olen, sizeof olen);
	oth.sum = htobe16(~ip4_cksum(sum, &oth, sizeof oth));

	/* send packet */
	if (ft_logout)
		csv_tcp4(&fl->eth->p->ts, &fl->dst, &fl->src, &oth, 0);
	ret = ip4_reply(fl, ip_proto_tcp, &oth, sizeof oth);
	return (ret);
}

/*
 * Reply to a SYN packet with a SYN/ACK with a very small window size.
 */
static int
tcp4_hello(const ip4_flow *fl, const tcp4_hdr *ith, size_t ilen)
{
	tcp4_hdr oth;
	uint32_t ack;
	uint16_t olen, sum;
	int ret;

	(void)ilen;

	/* fill in header */
	oth.sp = ith->dp;
	oth.dp = ith->sp;
	oth.seq = htobe32(FLYTRAP_TCP4_SEQ);
	ack = be32toh(ith->seq) + 1;
	oth.ack = htobe32(ack);
	oth.off_ns = (sizeof oth / 4U) << 4;
	oth.fl = TCP4_SYN | TCP4_ACK;
	oth.win = htobe16(0);
	oth.sum = htobe16(0);
	oth.urg = htobe16(0);

	/* compute pseudo-header checksum, then packet checksum */
	sum = ip4_cksum(0, &fl->dst, sizeof fl->dst);
	sum = ip4_cksum(sum, &fl->src, sizeof fl->src);
	sum = ip4_cksum(sum, &fl->proto, sizeof fl->proto);
	olen = htobe16(sizeof oth);
	sum = ip4_cksum(sum, &olen, sizeof olen);
	oth.sum = htobe16(~ip4_cksum(sum, &oth, sizeof oth));

	/* send packet */
	if (ft_logout)
		csv_tcp4(&fl->eth->p->ts, &fl->dst, &fl->src, &oth, 0);
	ret = ip4_reply(fl, ip_proto_tcp, &oth, sizeof oth);
	return (ret);
}

/*
 * Reply to a TCP packet with another which acknowledges receipt but
 * informs the peer that we don't have any free buffer space.
 */
static int
tcp4_please_hold(const ip4_flow *fl, const tcp4_hdr *ith, size_t ilen)
{
	tcp4_hdr oth;
	uint16_t olen, sum;
	int ret;

	(void)ilen;

	/* fill in header */
	oth.sp = ith->dp;
	oth.dp = ith->sp;
	oth.seq = htobe32(FLYTRAP_TCP4_SEQ);
	oth.ack = ith->seq;
	oth.off_ns = (sizeof oth / 4U) << 4;
	oth.fl = (ith->fl & TCP4_SYN) | TCP4_ACK;
	oth.win = htobe16(0);
	oth.sum = htobe16(0);
	oth.urg = htobe16(0);

	/* compute pseudo-header checksum, then packet checksum */
	sum = ip4_cksum(0, &fl->dst, sizeof fl->dst);
	sum = ip4_cksum(sum, &fl->src, sizeof fl->src);
	sum = ip4_cksum(sum, &fl->proto, sizeof fl->proto);
	olen = htobe16(sizeof oth);
	sum = ip4_cksum(sum, &olen, sizeof olen);
	oth.sum = htobe16(~ip4_cksum(sum, &oth, sizeof oth));

	/* send packet */
	if (ft_logout)
		csv_tcp4(&fl->eth->p->ts, &fl->dst, &fl->src, &oth, 0);
	ret = ip4_reply(fl, ip_proto_tcp, &oth, sizeof oth);
	return (ret);
}

/*
 * Reply to a FIN packet with a FIN/ACK.
 */
static int
tcp4_goodbye(const ip4_flow *fl, const tcp4_hdr *ith, size_t ilen)
{
	tcp4_hdr oth;
	uint16_t olen, sum;
	int ret;

	(void)ilen;

	/* fill in packet */
	oth.sp = ith->dp;
	oth.dp = ith->sp;
	oth.seq = htobe32(FLYTRAP_TCP4_SEQ);
	oth.ack = ith->seq;
	oth.off_ns = (sizeof oth / 4U) << 4;
	oth.fl = TCP4_FIN | TCP4_ACK;
	oth.win = htobe16(0);
	oth.sum = htobe16(0);
	oth.urg = htobe16(0);

	/* compute pseudo-header checksum, then packet checksum */
	sum = ip4_cksum(0, &fl->dst, sizeof fl->dst);
	sum = ip4_cksum(sum, &fl->src, sizeof fl->src);
	sum = ip4_cksum(sum, &fl->proto, sizeof fl->proto);
	olen = htobe16(sizeof oth);
	sum = ip4_cksum(sum, &olen, sizeof olen);
	oth.sum = htobe16(~ip4_cksum(sum, &oth, sizeof oth));

	/* send packet */
	if (ft_logout)
		csv_tcp4(&fl->eth->p->ts, &fl->dst, &fl->src, &oth, 0);
	ret = ip4_reply(fl, ip_proto_tcp, &oth, sizeof oth);
	return (ret);
}

/*
 * Analyze a captured TCP packet
 */
int
packet_analyze_tcp4(const ip4_flow *fl, const void *data, size_t len)
{
	const tcp4_hdr *th;
	size_t thlen;
	uint16_t sum;
	int ret;

	th = data;
	thlen = len >= sizeof *th ? (tcp4_hdr_off(th) * 4U) : sizeof *th;
	if (len < thlen) {
		ft_verbose("%d.%03d short TCP packet (%zd < %zd)",
		    fl->eth->p->ts.tv_sec, fl->eth->p->ts.tv_usec / 1000,
		    len, thlen);
		return (-1);
	}
	if ((sum = ~ip4_cksum(fl->sum, data, len)) != 0) {
		ft_verbose("%d.%03d invalid TCP checksum 0x%04hx",
		    fl->eth->p->ts.tv_sec, fl->eth->p->ts.tv_usec / 1000,
		    sum);
		return (-1);
	}
	data = (const uint8_t *)data + thlen;
	len -= thlen;
	ft_debug("tcp4 port %hu to %hu seq %lu ack %lu win %hu len %zu",
	    (unsigned short)be16toh(th->sp), (unsigned short)be16toh(th->dp),
	    (unsigned long)be32toh(th->seq), (unsigned long)be32toh(th->ack),
	    (unsigned short)be16toh(th->win), len);
	csv_tcp4(&fl->eth->p->ts, &fl->src, &fl->dst, th, len);
	if (th->fl & TCP4_SYN) {
		if (th->fl & TCP4_ACK)
			ret = tcp4_go_away(fl, th, len);
		else
			ret = tcp4_hello(fl, th, len);
	} else if (th->fl & TCP4_FIN) {
		/* closing connection */
		/*
		 * This is disabled for now, as I haven't found a way to
		 * handle FIN correctly without keeping connection state.
		 * We may consider doing so in the future if we find a
		 * clever way to represent state with a minimal amount of
		 * resources and without exposing ourselves to a DoS.
		 */
		ret = 0 && tcp4_goodbye(fl, th, len);
	} else if (th->fl & TCP4_RST) {
		/* ignore packet */
		ret = 0;
	} else if (len > 0) {
		ret = tcp4_please_hold(fl, th, len);
	} else {
		/* ignore packet */
		ret = 0;
	}
	return (ret);
}
