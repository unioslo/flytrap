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

#include <ft/endian.h>
#include <ft/ip4.h>

static inline int
t_compare_ip4(const ip4_addr *e, const ip4_addr *r)
{

	if (e->q != r->q) {
		t_verbose("expected %d.%d.%d.%d\n"
		    "received %d.%d.%d.%d\n",
		    e->o[0], e->o[1], e->o[2], e->o[3],
		    r->o[0], r->o[1], r->o[2], r->o[3]);
		return (0);
	}
	return (1);
}

static struct t_ip4p_case {
	const char		*desc;
	const char		*str;
	size_t			 len;
	ip4_addr		 addr;
} t_ip4p_cases[] = {
	{
		.desc	 = "empty",
		.str	 = "",
		.len	 = 0,
	},
	{
		.desc	 = "comma",
		.str	 = ",",
		.len	 = 0,
	},
	{
		.desc	 = "zero",
		.str	 = "0.0.0.0",
		.len	 = 7,
		.addr	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "zero comma",
		.str	 = "0.0.0.0,",
		.len	 = 7,
		.addr	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "one",
		.str	 = "1.1.1.1",
		.len	 = 7,
		.addr	 = { .o = { 1, 1, 1, 1 } },
	},
	{
		.desc	 = "broadcast",
		.str	 = "255.255.255.255",
		.len	 = 15,
		.addr	 = { .o = { 255, 255, 255, 255 } },
	},
	{
		.desc	 = "bad octet 1",
		.str	 = "256.0.0.0",
		.len	 = ~0U,
	},
	{
		.desc	 = "bad octet 2",
		.str	 = "0.256.0.0",
		.len	 = ~0U,
	},
	{
		.desc	 = "bad octet 3",
		.str	 = "0.0.256.0",
		.len	 = ~0U,
	},
	{
		.desc	 = "bad octet 4",
		.str	 = "0.0.0.256",
		.len	 = ~0U,
	},
	{
		.desc	 = "mangled",
		.str	 = "192.0.a.b",
		.len	 = ~0U,
	},
};

static int
t_ip4p(char **desc CRYB_UNUSED, void *arg)
{
	struct t_ip4p_case *t = arg;
	ip4_addr addr;
	const char *e;
	int ret;

	e = ip4_parse(t->str, &addr);
	if (t->len == ~0U) {
		ret = t_is_null(e);
	} else {
		ret = t_is_not_null(e);
		if (t->len > 0) {
			ret &= t_compare_ptr(t->str + t->len, e);
			ret &= t_compare_ip4(&t->addr, &addr);
		}
	}
	return (ret);
}

static int
t_prepare(int argc CRYB_UNUSED, char *argv[] CRYB_UNUSED)
{
	unsigned int i;

	for (i = 0; i < sizeof t_ip4p_cases / sizeof t_ip4p_cases[0]; ++i)
		t_add_test(t_ip4p, &t_ip4p_cases[i], t_ip4p_cases[i].desc ?
		    t_ip4p_cases[i].desc : t_ip4p_cases[i].str);
	return (0);
}

int
main(int argc, char *argv[])
{

	t_main(t_prepare, NULL, argc, argv);
}