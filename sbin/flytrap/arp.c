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

#include <ft/arp.h>
#include <ft/assert.h>
#include <ft/endian.h>
#include <ft/ethernet.h>
#include <ft/ip4.h>
#include <ft/log.h>

#include "flytrap.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

/* magic value for "never seen" */
#define ARP_NEVER	UINT64_MAX

/* min unanswered ARP requests before we claim an address */
#define ARP_MINREQ	     3

/* how long to wait (in ms) before claiming an address */
#define ARP_TIMEOUT	  3000

/* age (in ms) of an entry before it is considered stale */
#define ARP_STALE	 30000

/* age (in ms) of an entry before it is removed from the tree */
#define ARP_EXPIRE	300000

/*
 * A node in the tree.
 */
struct arpn {
	uint32_t	 addr;		/* network address */
	uint8_t		 plen;		/* prefix length */
	union {
		/* leaf node */
		uint64_t	 first;		/* first seen (ms) */
		/* inner node */
		uint64_t	 oldest;	/* oldest child */
	};
	union {
		/* leaf node */
		uint64_t	 last;		/* last seen (ms) */
		/* inner node */
		uint64_t	 newest;	/* newest child */
	};
	union {
		/* leaf node */
		struct {
			ether_addr	 ether;		/* Ethernet address */
			unsigned int	 nreq;		/* requests seen */
			int		 claimed:1;	/* claimed by us */
			int		 reserved:1;	/* reserved address */
		};
		/* inner node */
		struct {
			struct arpn	*sub[16];	/* children */
		};
	};
};

static struct arpn arp_root = { .first = ARP_NEVER };
static unsigned int narpn, nleaves;

#if 0
/*
 * Print the leaf nodes of a tree in order.
 */
static void
arp_print_tree(FILE *f, struct arpn *n)
{
	unsigned int i;

	if (n->plen == 32) {
		fprintf(f, "%u.%u.%u.%u",
		    (n->addr >> 24) & 0xff,
		    (n->addr >> 16) & 0xff,
		    (n->addr >> 8) & 0xff,
		    n->addr & 0xff);
		if (n->plen < 32)
			fprintf(f, "/%u", n->plen);
		fprintf(f, "\n");
	} else {
		for (i = 0; i < 16; ++i)
			if (n->sub[i] != NULL)
				arp_print_tree(f, n->sub[i]);
	}
}
#endif

/*
 * Create a node for the subnet of the specified prefix length which
 * contains the specified address.
 */
static struct arpn *
arp_new(uint32_t addr, uint8_t plen)
{
	struct arpn *n;

	if ((n = calloc(1, sizeof *n)) == NULL)
		return (NULL);
	narpn++;
	n->addr = addr & -(1 << (32 - plen));
	n->plen = plen;
	n->first = ARP_NEVER;
	n->last = 0;
	ft_debug("added node %08x/%d", n->addr, n->plen);
	return (n);
}

/*
 * Delete all children of a given node in a tree.
 */
static void
arp_delete(struct arpn *n)
{
	unsigned int i;

	if (n == NULL)
		return;
	if (n->plen == 32)
		nleaves--;
	else
		for (i = 0; i < 16; ++i)
			if (n->sub[i] != NULL)
				arp_delete(n->sub[i]);
	ft_debug("deleted node %08x/%d", n->addr, n->plen);
	narpn--;
	free(n);
}

/*
 * Expire
 */
static void
arp_expire(struct arpn *n, uint64_t cutoff)
{
	unsigned int i, ndel;

	if (n == NULL)
		n = &arp_root;
	ndel = narpn;
	ft_debug("expiring in %08x/%d", n->addr, n->plen);
	/* reset fences */
	n->first = ARP_NEVER;
	n->last = 0;
	/* iterate over children */
	for (i = 0; i < 16; ++i) {
		if (n->sub[i] == NULL)
			continue;
		if (n->sub[i]->plen < 32) {
			/* check descendants first */
			if (n->sub[i]->oldest < cutoff)
				arp_expire(n->sub[i], cutoff);
		}
		if (n->sub[i]->newest < cutoff) {
			/* expired or empty */
			arp_delete(n->sub[i]);
			n->sub[i] = NULL;
		}
		if (n->sub[i] != NULL) {
			/* update our fences */
			if (n->sub[i]->newest < n->oldest)
				n->oldest = n->sub[i]->newest;
			if (n->sub[i]->newest > n->newest)
				n->newest = n->sub[i]->newest;
		}
	}
	ndel -= narpn;
	ft_debug("expired %u nodes under %08x/%d", ndel, n->addr, n->plen);
}

/*
 * Periodic maintenance
 */
void
arp_periodic(struct timeval *tv)
{
	uint64_t now;

	now = tv->tv_sec * 1000;
	arp_expire(NULL, now - ARP_EXPIRE);
}

/*
 * Insert an address into a tree.
 */
static struct arpn *
arp_insert(struct arpn *n, uint32_t addr, uint64_t when)
{
	struct arpn *sn, *rn;
	uint32_t sub;
	uint8_t splen;

	if (n == NULL)
		n = &arp_root;
	if (n->plen == 32) {
		ft_assert(n->addr == addr);
		if (when < n->first)
			n->first = when;
		if (when > n->last)
			n->last = when;
		return (n);
	}
	splen = n->plen + 4;
	sub = (addr >> (32 - splen)) % 16;
	if ((sn = n->sub[sub]) == NULL) {
		if ((sn = arp_new(addr, splen)) == NULL)
			return (NULL);
		if (sn->plen == 32) {
			ft_verbose("arp: inserted %d.%d.%d.%d",
			    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
			    (addr >> 8) & 0xff, addr & 0xff);
			nleaves++;
		}
		n->sub[sub] = sn;
	}
	if ((rn = arp_insert(sn, addr, when)) == NULL)
		return (NULL);
	/* for non-leaf nodes, first / last means oldest / newest */
	if (sn->newest < n->oldest)
		n->oldest = sn->newest;
	if (sn->newest > n->newest)
		n->newest = sn->newest;
	return (rn);
}

/*
 * ARP registration
 */
int
arp_register(const ip4_addr *ip4, const ether_addr *ether, uint64_t when)
{
	struct arpn *an;

	if ((an = arp_insert(NULL, be32toh(ip4->q), when)) == NULL)
		return (-1);
	if (memcmp(&an->ether, ether, sizeof an->ether) != 0) {
		/* warn if the ip4_addr moved from one ether_addr to another */
		if (an->ether.o[0] || an->ether.o[1] || an->ether.o[2] ||
		    an->ether.o[3] || an->ether.o[4] || an->ether.o[5]) {
			ft_verbose("%d.%d.%d.%d moved"
			    " from %02x:%02x:%02x:%02x:%02x:%02x"
			    " to %02x:%02x:%02x:%02x:%02x:%02x",
			    ip4->o[0], ip4->o[1], ip4->o[2], ip4->o[3],
			    an->ether.o[0], an->ether.o[1], an->ether.o[2],
			    an->ether.o[3], an->ether.o[4], an->ether.o[5],
			    ether->o[0], ether->o[1], ether->o[2],
			    ether->o[3], ether->o[4], ether->o[5]);
		} else {
			ft_verbose("%d.%d.%d.%d registered"
			    " at %02x:%02x:%02x:%02x:%02x:%02x",
			    ip4->o[0], ip4->o[1], ip4->o[2], ip4->o[3],
			    ether->o[0], ether->o[1], ether->o[2],
			    ether->o[3], ether->o[4], ether->o[5]);
		}
		memcpy(&an->ether, ether, sizeof an->ether);
	}
	an->nreq = 0;
	return (0);
}

/*
 * ARP lookup
 */
int
arp_lookup(const ip4_addr *ip4, ether_addr *ether)
{
	struct arpn *an;

	ft_debug("ARP lookup %d.%d.%d.%d",
	    ip4->o[0], ip4->o[1], ip4->o[2], ip4->o[3]);
	an = &arp_root;
	if ((an = an->sub[ip4->o[0] / 16]) == NULL ||
	    (an = an->sub[ip4->o[0] % 16]) == NULL ||
	    (an = an->sub[ip4->o[1] / 16]) == NULL ||
	    (an = an->sub[ip4->o[1] % 16]) == NULL ||
	    (an = an->sub[ip4->o[2] / 16]) == NULL ||
	    (an = an->sub[ip4->o[2] % 16]) == NULL ||
	    (an = an->sub[ip4->o[3] / 16]) == NULL ||
	    (an = an->sub[ip4->o[3] % 16]) == NULL)
		return (-1);
	memcpy(ether, &an->ether, sizeof(ether_addr));
	ft_debug("%d.%d.%d.%d is"
	    " at %02x:%02x:%02x:%02x:%02x:%02x",
	    ip4->o[0], ip4->o[1], ip4->o[2], ip4->o[3],
	    ether->o[0], ether->o[1], ether->o[2],
	    ether->o[3], ether->o[4], ether->o[5]);
	return (0);
}

/*
 * Claim an IP address
 */
static int
arp_reply(const ether_flow *fl, const arp_pkt *iap, struct arpn *an)
{
	arp_pkt ap;

	(void)an;

	ap.htype = htobe16(arp_type_ether);
	ap.ptype = htobe16(arp_type_ip4);
	ap.hlen = 6;
	ap.plen = 4;
	ap.oper = htobe16(arp_oper_is_at);
	memcpy(&ap.sha, &fl->p->i->ether, sizeof(ether_addr));
	memcpy(&ap.spa, &iap->tpa, sizeof(ip4_addr));
	memcpy(&ap.tha, &iap->sha, sizeof(ether_addr));
	memcpy(&ap.tpa, &iap->spa, sizeof(ip4_addr));
	if (ethernet_reply(fl, &ap, sizeof ap) != 0)
		return (-1);
	return (0);
}

/*
 * Register a reserved address
 */
int
arp_reserve(const ip4_addr *addr)
{
	struct arpn *an;

	ft_debug("arp: reserving %d.%d.%d.%d",
	    addr->o[0], addr->o[1], addr->o[2], addr->o[3]);
	if ((an = arp_insert(NULL, be32toh(addr->q), 0)) == NULL)
		return (-1);
	an->reserved = 1;
	return (0);
}

/*
 * Analyze a captured ARP packet
 */
int
packet_analyze_arp(const ether_flow *fl, const void *data, size_t len)
{
	const arp_pkt *ap;
	struct arpn *an;
	uint64_t when;

	if (len < sizeof(arp_pkt)) {
		ft_verbose("%d.%03d short ARP packet (%zd < %zd)",
		    fl->p->ts.tv_sec, fl->p->ts.tv_usec / 1000,
		    len, sizeof(arp_pkt));
		return (-1);
	}
	ap = (const arp_pkt *)data;
	ft_debug("\tARP htype 0x%04hx ptype 0x%04hx hlen %hd plen %hd",
	    be16toh(ap->htype), be16toh(ap->ptype), ap->hlen, ap->plen);
	if (be16toh(ap->htype) != arp_type_ether || ap->hlen != 6 ||
	    be16toh(ap->ptype) != arp_type_ip4 || ap->plen != 4) {
		ft_debug("\tARP packet ignored");
		return (0);
	}
	switch (be16toh(ap->oper)) {
	case arp_oper_who_has:
		ft_debug("\twho-has %d.%d.%d.%d tell %d.%d.%d.%d",
		    ap->tpa.o[0], ap->tpa.o[1], ap->tpa.o[2], ap->tpa.o[3],
		    ap->spa.o[0], ap->spa.o[1], ap->spa.o[2], ap->spa.o[3]);
		break;
	case arp_oper_is_at:
		ft_debug("\t%d.%d.%d.%d is-at %02x:%02x:%02x:%02x:%02x:%02x",
		    ap->tpa.o[0], ap->tpa.o[1], ap->tpa.o[2], ap->tpa.o[3], ap->tha.o[0],
		    ap->tha.o[1], ap->tha.o[2], ap->tha.o[3], ap->tha.o[4], ap->tha.o[5]);
		break;
	default:
		ft_verbose("%d.%03d unknown ARP operation 0x%04x", be16toh(ap->oper));
		return (0);
	}
	when = fl->p->ts.tv_sec * 1000 + fl->p->ts.tv_usec / 1000;
	switch (be16toh(ap->oper)) {
	case arp_oper_who_has:
		/* ARP request */
		if (dst_set && !ip4s_lookup(dst_set, be32toh(ap->tpa.q))) {
			ft_debug("\ttarget address is out of bounds");
			break;
		}
		/* register sender */
		arp_register(&ap->spa, &ap->sha, when);
		/*
		 * Note that arp_insert() sets an->last = when so we don't
		 * have to, but leaves an->first untouched.  For new
		 * nodes, this is the magic value ARP_NEVER.
		 */
		if ((an = arp_insert(NULL, be32toh(ap->tpa.q), when)) == NULL)
			return (-1);
		if (an->first == ARP_NEVER) {
			/* new entry */
			an->first = when;
		} else {
			ft_verbose("%d.%d.%d.%d: last seen %d.%03d",
			    ap->tpa.o[0], ap->tpa.o[1], ap->tpa.o[2], ap->tpa.o[3],
			    an->last / 1000, an->last % 1000);
		}
		if (an->reserved) {
			/* ignore */
			ft_debug("\ttarget address is reserved");
			an->nreq = 0;
		} else if (an->claimed) {
			/* already ours, refresh */
			ft_debug("refreshing %d.%d.%d.%d",
			    ap->tpa.o[0], ap->tpa.o[1], ap->tpa.o[2], ap->tpa.o[3]);
			an->nreq = 0;
			if (arp_reply(fl, ap, an) != 0)
				return (-1);
		} else if (an->nreq == 0 || when - an->last >= ARP_STALE) {
			/* new or stale, start over */
			an->nreq = 1;
			an->first = when;
		} else if (an->nreq >= ARP_MINREQ &&
		    when - an->first >= ARP_TIMEOUT) {
			/* claim new address */
			ft_verbose("claiming %d.%d.%d.%d nreq = %d", ap->tpa.o[0],
			    ap->tpa.o[1], ap->tpa.o[2], ap->tpa.o[3], an->nreq);
			an->claimed = 1;
			an->nreq = 0;
			if (arp_reply(fl, ap, an) != 0)
				return (-1);
		} else {
			an->nreq++;
			an->last = when;
		}
		break;
	case arp_oper_is_at:
		/* ARP reply */
		arp_register(&ap->spa, &ap->sha, when);
		arp_register(&ap->tpa, &ap->tha, when);
		break;
	}
	/* run expiry, assume packet time is <= current time */
	if (arp_root.oldest < when - ARP_EXPIRE) {
		arp_expire(&arp_root, when - ARP_EXPIRE);
		ft_debug("%u nodes / %u leaves in tree", narpn, nleaves);
	}
	return (0);
}
