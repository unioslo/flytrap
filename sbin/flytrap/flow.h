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

#ifndef FLYTRAP_FLOW_H_INCLUDED
#define FLYTRAP_FLOW_H_INCLUDED

struct iface;
struct packet;
struct timeval;

#define FLYTRAP_ETHER_ADDR { 0x02, 0x00, 0x18, 0x11, 0x09, 0x02 }
extern ether_addr flytrap_ether_addr;

#define FLYTRAP_TCP4_SEQ 0x18110902U

typedef struct ether_flow {
	const struct packet	*p;
	ether_addr		 src;
	ether_addr		 dst;
	uint16_t		 type;
	uint16_t		 len;
} ether_flow;

extern ip4s_node *src_set;
extern ip4s_node *dst_set;

typedef struct ip4_flow {
	const struct ether_flow	*eth;
	/* pseudo-header */
	union {
		uint8_t		 pseudo[12];
		struct {
			ip4_addr	 src;
			ip4_addr	 dst;
			uint16_t	 proto;
			uint16_t	 len;
		} __attribute__((__packed__));
	};
	uint16_t	 sum;
} ip4_flow;

int	 arp_register(const ip4_addr *, const ether_addr *);
int	 arp_lookup(const ip4_addr *, ether_addr *);

int	 ethernet_send(struct iface *, ether_type, const ether_addr *,
    const void *, size_t);
int	 ethernet_reply(const struct ether_flow *, const void *, size_t);

int	 ip4_reply(const ip4_flow *, ip_proto, const void *, size_t);

int	 packet_analyze_ethernet(const struct packet *, const void *, size_t);
int	 packet_analyze_arp(const struct ether_flow *, const void *, size_t);
int	 packet_analyze_ip4(const struct ether_flow *, const void *, size_t);
int	 packet_analyze_icmp4(const struct ip4_flow *, const void *, size_t);
int	 packet_analyze_udp4(const struct ip4_flow *, const void *, size_t);
int	 packet_analyze_tcp4(const struct ip4_flow *, const void *, size_t);

int	 csv_packet4(const struct timeval *,
    const ip4_addr *, int, const ip4_addr *, int,
    const char *, size_t, const char *, ...);

#endif
