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

#include <stdint.h>
#include <stdio.h>

#include <cryb/test.h>

#include "t_ip4.h"

static struct t_ip4a_case {
	const char		*desc;
	const char		*str;
	size_t			 len;
	ip4_addr		 addr;
} t_ip4a_cases[] = {
	{
		.desc	 = "empty",
		.str	 = "",
		.len	 = 0,
		.addr	 = { .o = { 165, 165, 165, 165 } },
	},
	{
		.desc	 = "comma",
		.str	 = ",",
		.len	 = 0,
		.addr	 = { .o = { 165, 165, 165, 165 } },
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
		.desc	 = "valid",
		.str	 = "172.16.32.64",
		.len	 = 12,
		.addr	 = { .o = { 172, 16, 32, 64 } },
	},
	{
		.desc	 = "broadcast",
		.str	 = "255.255.255.255",
		.len	 = 15,
		.addr	 = { .o = { 255, 255, 255, 255 } },
	},
	{
		.desc	 = "leading zeroes 1",
		.str	 = "0172.016.032.064",
		.len	 = 16,
		.addr	 = { .o = { 172, 16, 32, 64 } },
	},
	{
		.desc	 = "leading zeroes 2",
		.str	 = "00172.0016.0032.0064",
		.len	 = 20,
		.addr	 = { .o = { 172, 16, 32, 64 } },
	},
	{
		.desc	 = "leading zeroes 3",
		.str	 = "000172.00016.00032.00064",
		.len	 = 24,
		.addr	 = { .o = { 172, 16, 32, 64 } },
	},
	{
		.desc	 = "octet overflow 1",
		.str	 = "1720.16.32.64",
		.len	 = ~0U,
		.addr	 = { .o = { 165, 165, 165, 165 } },
	},
	{
		.desc	 = "octet overflow 2",
		.str	 = "172.1600.32.64",
		.len	 = ~0U,
		.addr	 = { .o = { 172, 165, 165, 165 } },
	},
	{
		.desc	 = "octet overflow 3",
		.str	 = "172.16.320.64",
		.len	 = ~0U,
		.addr	 = { .o = { 172, 16, 165, 165 } },
	},
	{
		.desc	 = "octet overflow 4",
		.str	 = "172.16.32.640",
		.len	 = ~0U,
		.addr	 = { .o = { 172, 16, 32, 165 } },
	},
	{
		.desc	 = "bad separator 1",
		.str	 = "172-16.32.64",
		.len	 = ~0U,
		.addr	 = { .o = { 172, 165, 165, 165 } },
	},
	{
		.desc	 = "bad separator 2",
		.str	 = "172.16-32.64",
		.len	 = ~0U,
		.addr	 = { .o = { 172, 16, 165, 165 } },
	},
	{
		.desc	 = "bad separator 3",
		.str	 = "172.16.32-64",
		.len	 = ~0U,
		.addr	 = { .o = { 172, 16, 32, 165 } },
	},
	{
		.desc	 = "mangled",
		.str	 = "172.16.32.sixty-four",
		.len	 = ~0U,
		.addr	 = { .o = { 172, 16, 32, 165 } },
	},
};

static int
t_ip4a(char **desc CRYB_UNUSED, void *arg)
{
	struct t_ip4a_case *t = arg;
	ip4_addr addr;
	const char *e;
	int ret;

	addr.q = 0xa5a5a5a5U;
	e = ip4_parse(t->str, &addr);
	if (t->len == ~0U) {
		ret = t_is_null(e);
	} else {
		ret = t_is_not_null(e);
		if (t->len > 0)
			ret &= t_compare_ptr(t->str + t->len, e);
	}
	ret &= t_compare_ip4_addr(&t->addr, &addr);
	return (ret);
}

static int
t_prepare(int argc CRYB_UNUSED, char *argv[] CRYB_UNUSED)
{
	unsigned int i;

	for (i = 0; i < sizeof t_ip4a_cases / sizeof t_ip4a_cases[0]; ++i)
		t_add_test(t_ip4a, &t_ip4a_cases[i],
		    "%s", t_ip4a_cases[i].desc);
	return (0);
}

int
main(int argc, char *argv[])
{

	t_main(t_prepare, NULL, argc, argv);
}
