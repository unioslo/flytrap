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

#ifndef T_IP4_H_INCLUDED
#define T_IP4_H_INCLUDED

#include <ft/endian.h>
#include <ft/ip4.h>

static inline int
t_compare_ip4_addr(const ip4_addr *e, const ip4_addr *r)
{

	if (e->q != r->q) {
		t_printv("expected %d.%d.%d.%d\n"
		    "received %d.%d.%d.%d\n",
		    e->o[0], e->o[1], e->o[2], e->o[3],
		    r->o[0], r->o[1], r->o[2], r->o[3]);
		return (0);
	}
	return (1);
}

static inline int
t_ip4s_present(const ip4s_node *set, const ip4_addr *addr)
{

	if (ip4s_lookup(set, be32toh(addr->q)) == 0) {
		t_printv("expected %d.%d.%d.%d present\n",
		    addr->o[0], addr->o[1], addr->o[2], addr->o[3]);
		return (0);
	}
	return (1);
}

static inline int
t_ip4s_absent(const ip4s_node *set, const ip4_addr *addr)
{

	if (ip4s_lookup(set, be32toh(addr->q)) != 0) {
		t_printv("expected %d.%d.%d.%d absent\n",
		    addr->o[0], addr->o[1], addr->o[2], addr->o[3]);
		return (0);
	}
	return (1);
}

#endif
