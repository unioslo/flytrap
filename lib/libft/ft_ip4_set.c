/*-
 * Copyright (c) 2015-2016 The University of Oslo
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ft/ctype.h>
#include <ft/ip4.h>

/*
 * How many bits to process at a time.  Lower values improve aggregation
 * but can greatly increase the memory footprint.
 */
#define IP4S_BITS	 4
#define IP4S_SUBS	 (1U << IP4S_BITS)

/*
 * A node in the tree.
 */
struct ip4s_node {
	uint32_t	 addr;		/* network address */
	uint8_t		 plen;		/* prefix length */
	int		 leaf:1;	/* leaf node flag */
	unsigned long	 coverage;	/* addresses in subtree */
	ip4s_node	*sub[IP4S_SUBS];/* subtrees */
};

/*
 * Print the leaf nodes of a tree in order.
 */
void
ip4s_fprint(FILE *f, const ip4s_node *n)
{
	unsigned int i;

	if (n->leaf) {
		fprintf(f, "%u.%u.%u.%u",
		    (n->addr >> 24) & 0xff,
		    (n->addr >> 16) & 0xff,
		    (n->addr >> 8) & 0xff,
		    n->addr & 0xff);
		if (n->plen < 32)
			fprintf(f, "/%u", n->plen);
		fprintf(f, "\n");
	} else {
		for (i = 0; i < IP4S_SUBS; ++i)
			if (n->sub[i] != NULL)
				ip4s_fprint(f, n->sub[i]);
	}
}

/*
 * Allocate a new, empty tree.
 */
ip4s_node *
ip4s_new(void)
{
	ip4s_node *n;

	if ((n = calloc(1, sizeof(ip4s_node))) == NULL)
		return (NULL);
	n->leaf = 1;
	return (n);
}

/*
 * Delete all children of a node.
 */
static void
ip4s_delete(ip4s_node *n)
{
	unsigned int i;

	for (i = 0; i < IP4S_SUBS; ++i) {
		if (n->sub[i] != NULL) {
			ip4s_delete(n->sub[i]);
			free(n->sub[i]);
			n->sub[i] = NULL;
		}
	}
}

/*
 * Destroy a tree.
 */
void
ip4s_destroy(ip4s_node *n)
{

	ip4s_delete(n);
	free(n);
}

/*
 * Insert a range of addresses (specified as first and last) into a tree.
 */
int
ip4s_insert(ip4s_node *n, uint32_t first, uint32_t last)
{
	ip4s_node *sn;
	uint32_t mask, fsub, lsub;
	unsigned int i, splen;
	int ret;

	/*
	 * Compute the host mask for this subnet.  This is the inverse of
	 * the netmask.
	 */
	mask = 0xffffffffLU >> n->plen;

	/*
	 * Shortcut: already full!
	 */
	if (n->coverage == mask + 1LU)
		return (0);

	/*
	 * Clip the range to our subnet so the caller doesn't have to (see
	 * loop below).
	 */
	if (first < n->addr)
		first = n->addr;
	if (last > (n->addr | mask))
		last = n->addr | mask;

	/*
	 * Shortcut: the inserted range covers the entire subnet.
	 */
	if (first == n->addr && last == (n->addr | mask)) {
		ip4s_delete(n);
		n->leaf = 1;
		n->coverage = mask + 1LU; /* equivalent to size of subnet */
		return (0);
	}

	/*
	 * Compute the prefix length for the next recursion level and find
	 * out which child node(s) we will have to descend into.
	 */
	splen = n->plen + IP4S_BITS;
	fsub = (first >> (32 - splen)) % IP4S_SUBS;
	lsub = (last >> (32 - splen)) % IP4S_SUBS;

	/*
	 * Descend into each covered child.
	 */
	for (i = fsub; i <= lsub; ++i) {
		/*
		 * Create a new node.
		 */
		if ((sn = n->sub[i]) == NULL) {
			if ((sn = calloc(1, sizeof *sn)) == NULL)
				return (-1);
			sn->addr = n->addr | (i << (32 - splen));
			sn->plen = splen;
			sn->leaf = 1;
			n->sub[i] = sn;
			n->leaf = 0;
		}
		/*
		 * Insert into subnet and adjust our coverage number.
		 */
		n->coverage -= sn->coverage;
		ret = ip4s_insert(sn, first, last);
		n->coverage += sn->coverage;
		if (ret != 0)
			return (ret);
	}

	/*
	 * Perform aggregation
	 */
	if (n->coverage == mask + 1LU) {
		ip4s_delete(n);
		n->leaf = 1;
	}

	return (0);
}

/*
 * Remove a range of addresses (specified as first and last) from a tree.
 */
int
ip4s_remove(ip4s_node *n, uint32_t first, uint32_t last)
{
	ip4s_node *sn;
	uint32_t addr, fsub, lsub, mask, smask;
	unsigned int i, splen;

	/*
	 * Shortcut: already empty!
	 */
	if (n->coverage == 0)
		return (0);

	/*
	 * Compute the host mask for this subnet.  This is the inverse of
	 * the netmask.
	 */
	mask = 0xffffffffLU >> n->plen;

	/*
	 * Clip the range to our subnet so the caller doesn't have to (see
	 * loop below).
	 */
	if (first < n->addr)
		first = n->addr;
	if (last > (n->addr | mask))
		last = n->addr | mask;

	/*
	 * Shortcut: the removed range covers the entire subnet.  It is up
	 * to our parent (if any) to delete us.
	 */
	if (first == n->addr && last == (n->addr | mask)) {
		ip4s_delete(n);
		n->leaf = 1;
		n->coverage = 0;
		return (0);
	}

	/*
	 * Compute the prefix length for the next recursion level and find
	 * out which child node(s) we will have to descend into.
	 */
	splen = n->plen + IP4S_BITS;
	smask = mask >> IP4S_BITS;
	fsub = (first >> (32 - splen)) % IP4S_SUBS;
	lsub = (last >> (32 - splen)) % IP4S_SUBS;

	/*
	 * If we are a full leaf, we have to create child nodes for the
	 * subtrees we aren't removing.
	 */
	if (n->leaf && n->coverage == mask + 1LU) {
		n->coverage = 0;
		n->leaf = 0;
		for (i = 0; i < IP4S_SUBS; ++i) {
			addr = n->addr | (i << (32 - splen));
			if (!(first <= addr && last >= (addr | smask))) {
				if ((sn = calloc(1, sizeof *sn)) == NULL)
					return (-1);
				sn->addr = addr;
				sn->plen = splen;
				sn->leaf = 1;
				sn->coverage = smask + 1LU;
				n->sub[i] = sn;
				n->coverage += sn->coverage;
			}
		}
	}

	/*
	 * Either completely remove or descend into covered children.
	 */
	for (i = fsub; i <= lsub; ++i) {
		if ((sn = n->sub[i]) != NULL) {
			n->coverage -= sn->coverage;
			ip4s_remove(sn, first, last);
			n->coverage += sn->coverage;
			if (sn->coverage == 0) {
				free(sn);
				n->sub[i] = NULL;
			}
		}
	}

	return (0);
}

/*
 * Look up an address in a tree.
 */
int
ip4s_lookup(const ip4s_node *n, uint32_t addr)
{
	uint32_t mask, sub;

	mask = 0xffffffffLU >> n->plen;

	/* within our subtree? */
	if (addr >= n->addr && addr <= (n->addr | mask)) {
		/* fully covered? */
		if (n->coverage == mask + 1LU)
			return (1);
		/* descend */
		sub = (addr >> (32 - n->plen - IP4S_BITS)) % IP4S_SUBS;
		if (n->sub[sub] != NULL)
			return (ip4s_lookup(n->sub[sub], addr));
	}
	return (0);
}

/*
 * Return the number of addresses in a tree.
 */
unsigned long
ip4s_count(const ip4s_node *n)
{

	return (n->coverage);
}
