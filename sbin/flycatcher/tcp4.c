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

#include <sys/time.h>

#include <stddef.h>
#include <stdint.h>

#include <fc/endian.h>
#include <fc/log.h>

#include "flycatcher.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

/*
 * Analyze a captured TCP packet
 */
int
packet_analyze_tcp4(const ipv4_flow *fl, const void *data, size_t len)
{
	char flags[] = "NCEUAPRSF";
	const tcp4_hdr *th;
	size_t thlen;
	unsigned int bit, mask;
	uint16_t sum;

	th = data;
	thlen = len >= sizeof *th ? tcp4_hdr_off(th) : sizeof *th;
	if (len < thlen) {
		fc_notice("%d.%03d short TCP packet (%zd < %zd)",
		    fl->p->ts.tv_sec, fl->p->ts.tv_usec / 1000,
		    len, thlen);
		return (-1);
	}
	if ((sum = ~ip_cksum(fl->sum, data, len)) != 0) {
		fc_notice("%d.%03d invalid TCP checksum 0x%04hx",
		    fl->p->ts.tv_sec, fl->p->ts.tv_usec / 1000, sum);
		return (-1);
	}
	data = (const uint8_t *)data + thlen;
	len -= thlen;
	if (!tcp4_hdr_ns(th))
		flags[0] = '-';
	for (bit = 1, mask = 0x80; mask > 0; ++bit, mask >>= 1)
		if (!(th->fl & mask))
			flags[bit] = '-';
	log_packet4(&fl->p->ts, &fl->src, be16toh(th->sp),
	    &fl->dst, be16toh(th->dp), "TCP", len, flags);
	return (0);
}
