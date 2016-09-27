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

#include "t_ip4.h"

static struct t_ip4r_case {
	const char		*desc;
	const char		*str;
	size_t			 len;
	ip4_addr		 first;
	ip4_addr		 last;
} t_ip4r_cases[] = {
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
		.first	 = { .o = { 0, 0, 0, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "zero,",
		.str	 = "0.0.0.0,",
		.len	 = 7,
		.first	 = { .o = { 0, 0, 0, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "zero-zero",
		.str	 = "0.0.0.0-0.0.0.0",
		.len	 = 15,
		.first	 = { .o = { 0, 0, 0, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "zero-zero,",
		.str	 = "0.0.0.0-0.0.0.0,",
		.len	 = 15,
		.first	 = { .o = { 0, 0, 0, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "zero/zero",
		.str	 = "0.0.0.0/0",
		.len	 = 9,
		.first	 = { .o = { 0, 0, 0, 0 } },
		.last	 = { .o = { 255, 255, 255, 255 } },
	},
	{
		.desc	 = "zero/zero,",
		.str	 = "0.0.0.0/0,",
		.len	 = 9,
		.first	 = { .o = { 0, 0, 0, 0 } },
		.last	 = { .o = { 255, 255, 255, 255 } },
	},
	{
		.desc	 = "inverted",
		.str	 = "255.255.255.255-0.0.0.0",
		.len	 = ~0U,
		.first	 = { .o = { 255, 255, 255, 255 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "alpha-good",
		.str	 = "a.b.c.d-192.0.2.255",
		.len	 = 0,
		.first	 = { .o = { 0, 0, 0, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "bad-good",
		.str	 = "192.0.2.256-192.0.2.0",
		.len	 = ~0U,
		.first	 = { .o = { 192, 0, 2, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "good-alpha",
		.str	 = "192.0.2.0-a.b.c.d",
		.len	 = ~0U,
		.first	 = { .o = { 192, 0, 2, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "good-bad",
		.str	 = "192.0.2.0-192.0.2.256",
		.len	 = ~0U,
		.first	 = { .o = { 192, 0, 2, 0 } },
		.last	 = { .o = { 192, 0, 2, 0 } },
	},
	{
		.desc	 = "alpha/good",
		.str	 = "a.b.c.d/24",
		.len	 = 0,
		.first	 = { .o = { 0, 0, 0, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "bad/good",
		.str	 = "192.0.2.256/24",
		.len	 = ~0U,
		.first	 = { .o = { 192, 0, 2, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "good/alpha",
		.str	 = "192.0.2.0/p",
		.len	 = ~0U,
		.first	 = { .o = { 192, 0, 2, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "good/bad",
		.str	 = "192.0.2.0/33",
		.len	 = ~0U,
		.first	 = { .o = { 192, 0, 2, 0 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
	{
		.desc	 = "unaligned",
		.str	 = "192.0.2.3/24",
		.len	 = ~0U,
		.first	 = { .o = { 192, 0, 2, 3 } },
		.last	 = { .o = { 0, 0, 0, 0 } },
	},
};

static int
t_ip4r(char **desc CRYB_UNUSED, void *arg)
{
	struct t_ip4r_case *t = arg;
	ip4_addr first, last;
	const char *e;
	int ret;

	first.q = last.q = 0;
	e = ip4_parse_range(t->str, &first, &last);
	if (t->len == ~0U) {
		ret = t_is_null(e);
	} else {
		ret = t_is_not_null(e);
		ret &= t_compare_ptr(t->str + t->len, e);
	}
	ret &= t_compare_ip4_addr(&t->first, &first);
	ret &= t_compare_ip4_addr(&t->last, &last);
	return (ret);
}

static int
t_prepare(int argc CRYB_UNUSED, char *argv[] CRYB_UNUSED)
{
	unsigned int i;

	for (i = 0; i < sizeof t_ip4r_cases / sizeof t_ip4r_cases[0]; ++i)
		t_add_test(t_ip4r, &t_ip4r_cases[i], t_ip4r_cases[i].desc ?
		    t_ip4r_cases[i].desc : t_ip4r_cases[i].str);
	return (0);
}

int
main(int argc, char *argv[])
{

	t_main(t_prepare, NULL, argc, argv);
}
