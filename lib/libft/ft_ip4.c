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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <ft/ctype.h>
#include <ft/endian.h>
#include <ft/ip4.h>

/*
 * Convert dotted-quad to IPv4 address
 */
const char *
ip4_parse(const char *dqs, ip4_addr *addr)
{
	const char *s;
	int i, o;

	s = dqs;
	if (!is_digit(*s))
		return (s);
	for (i = 0; i < 4; ++i) {
		if ((i > 0 && *s++ != '.') || !is_digit(*s))
			return (NULL);
		for (o = 0; is_digit(*s); s++) {
			o = o * 10 + *s - '0';
			if (o > 255)
				return (NULL);
		}
		addr->o[i] = o;
	}
	return (s);
}

/*
 * Parse a string which contains either a single address, a pair of
 * addresses separated by a hyphen, or a range in CIDR notation.
 */
const char *
ip4_parse_range(const char *line, ip4_addr *first, ip4_addr *last)
{
	ip4_addr mask;
	const char *p, *q;
	int plen;

	/* isolate and parse the first address */
	if ((q = ip4_parse(p = line, first)) == NULL)
		return (NULL);
	p = q + 1;

	/* one of three syntaxes */
	if (*q == '-') {
		/* two addresses separated by a hyphen */
		if ((q = ip4_parse(p, last)) == NULL || q == p)
			return (NULL);
		if (be32toh(first->q) > be32toh(last->q))
			return (NULL);
	} else if (*q == '/') {
		/* subnet in CIDR notation */
		for (plen = 0, q = p; is_digit(*q); q++) {
			plen = plen * 10 + *q - '0';
			if (plen > 32)
				return (NULL);
		}
		mask.q = htobe32(0xffffffffLU >> plen);
		if (first->q & mask.q)
			return (NULL);
		last->q = first->q | mask.q;
	} else {
		/* single address */
		*last = *first;
	}
	return (q);
}

/*
 * IPv4 16-bit checksum
 */
uint16_t
ip4_cksum(uint16_t isum, const void *data, size_t len)
{
	const uint16_t *w;
	uint32_t sum;

	for (w = data, sum = isum; len > 1; len -= 2, ++w)
		sum += be16toh(*w);
	if (len)
		sum += *(const uint8_t *)w << 8;
	while (sum > 0xffff)
		sum -= 0xffff;
	return (sum);
}
