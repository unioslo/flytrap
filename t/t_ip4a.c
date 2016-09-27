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

#include <stdint.h>
#include <stdio.h>

#include <cryb/test.h>

#include <ft/assert.h>
#include <ft/endian.h>
#include <ft/ip4.h>

static struct t_ip4s_case {
	const char		*desc;
	const char		*insert;
	const char		*remove;
	unsigned long		 count;
	const char		*present;
	const char		*absent;
} t_ip4s_cases[] = {
	{
		.desc		 = "empty",
		.count		 = 0,
	},
	{
		.desc		 = "full",
		.insert		 = "0.0.0.0/0",
		.count		 = (1LU << 32),
		.present	 = "0.0.0.0,127.255.255.255,128.0.0.0,255.255.255.255",
	},
	{
		.desc		 = "half full",
		.insert		 = "0.0.0.0/1",
		.count		 = (1LU << 31),
		.present	 = "0.0.0.0,127.255.255.255",
		.absent		 = "128.0.0.0,255.255.255.255",
	},
	{
		.desc		 = "half empty",
		.insert		 = "0.0.0.0/0",
		.remove		 = "128.0.0.0/1",
		.count		 = (1LU << 31),
		.present	 = "0.0.0.0,127.255.255.255",
		.absent		 = "128.0.0.0,255.255.255.255",
	},
	{
		.desc		 = "single insertion",
		.insert		 = "172.16.23.42",
		.count		 = 1,
		.present	 = "172.16.23.42",
		.absent		 = "0.0.0.0,172.16.23.41,172.16.23.43,255.255.255.255",
	},
	{
		.desc		 = "single removal",
		.insert		 = "0.0.0.0/0",
		.remove		 = "172.16.23.42",
		.count		 = (1LU << 32) - 1,
		.present	 = "0.0.0.0,172.16.23.41,172.16.23.43,255.255.255.255",
		.absent		 = "172.16.23.42",
	},
	{
		.desc		 = "unaligned insertion",
		.insert		 = "172.16.0.0/15",
		.count		 = (1LU << 17),
		.present	 = "172.16.0.0,172.17.255.255",
		.absent		 = "0.0.0.0,172.15.255.255,172.18.0.0,255.255.255.255",
	},
	{
		.desc		 = "unaligned removal",
		.insert		 = "0.0.0.0/0",
		.remove		 = "172.16.0.0/15",
		.count		 = (1LU << 32) - (1LU << 17),
		.present	 = "0.0.0.0,172.15.255.255,172.18.0.0,255.255.255.255",
		.absent		 = "172.16.0.0,172.17.255.255",
	},
};

static int
t_ip4a(char **desc CRYB_UNUSED, void *arg)
{
	struct t_ip4s_case *t = arg;
	ip4_addr addr, first, last;
	const char *p, *q;
	ip4s_node *n;
	int ret;

	n = ip4s_new();
	if (!t_is_not_null(n))
		return (0);
	for (p = q = t->insert; q != NULL && *q != '\0'; p = q + 1) {
		q = ip4_parse_range(p, &first, &last);
		ft_assert(q != NULL && (*q == '\0' || *q == ','));
		if (ip4s_insert(n, be32toh(first.q), be32toh(last.q)) != 0)
			return (-1);
	}
	for (p = q = t->remove; q != NULL && *q != '\0'; p = q + 1) {
		q = ip4_parse_range(p, &first, &last);
		ft_assert(q != NULL && (*q == '\0' || *q == ','));
		if (ip4s_remove(n, be32toh(first.q), be32toh(last.q)) != 0)
			return (-1);
	}
	ret = t_compare_ul(t->count, ip4s_count(n));
	for (p = q = t->present; q != NULL && *q != '\0'; p = q + 1) {
		q = ip4_parse(p, &addr);
		ft_assert(q != NULL && (*q == '\0' || *q == ','));
		if (ip4s_lookup(n, be32toh(addr.q)) != 1) {
			t_verbose("expected %d.%d.%d.%d present\n",
			    addr.o[0], addr.o[1], addr.o[2], addr.o[3]);
			ret = 0;
		}
	}
	for (p = q = t->absent; q != NULL && *q != '\0'; p = q + 1) {
		q = ip4_parse(p, &addr);
		ft_assert(q != NULL && (*q == '\0' || *q == ','));
		if (ip4s_lookup(n, be32toh(addr.q)) != 0) {
			t_verbose("expected %d.%d.%d.%d absent\n",
			    addr.o[0], addr.o[1], addr.o[2], addr.o[3]);
			ret = 0;
		}
	}
	ip4s_destroy(n);
	return (ret);
}

static int
t_prepare(int argc CRYB_UNUSED, char *argv[] CRYB_UNUSED)
{
	unsigned int i;

	for (i = 0; i < sizeof t_ip4s_cases / sizeof t_ip4s_cases[0]; ++i)
		t_add_test(t_ip4a, &t_ip4s_cases[i], t_ip4s_cases[i].desc);
	return (0);
}

int
main(int argc, char *argv[])
{

	t_main(t_prepare, NULL, argc, argv);
}
