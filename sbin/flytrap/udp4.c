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

#include <ft/endian.h>
#include <ft/ethernet.h>
#include <ft/ip4.h>
#include <ft/log.h>

#include "flytrap.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

/*
 * Analyze a captured UDP packet
 */
int
packet_analyze_udp4(ip4_flow *fl, const void *data, size_t len)
{
	const udp4_hdr *uh;
	uint16_t sum;

	uh = data;
	if (len < sizeof *uh) {
		ft_notice("%d.%03d short UDP packet (%zd < %zd)",
		    fl->eth->p->ts.tv_sec, fl->eth->p->ts.tv_usec / 1000,
		    len, sizeof *uh);
		return (-1);
	}
	if (uh->sum != 0 &&
	    (sum = ~ip4_cksum(fl->sum, data, len)) != 0) {
		ft_notice("%d.%03d invalid UDP checksum 0x%04hx",
		    fl->eth->p->ts.tv_sec, fl->eth->p->ts.tv_usec / 1000,
		    sum);
		return (-1);
	}
	data = uh + 1;
	len -= sizeof *uh;
	csv_packet4(&fl->eth->p->ts, &fl->src, be16toh(uh->sp),
	    &fl->dst, be16toh(uh->dp), "UDP", len, "");
	return (0);
}
