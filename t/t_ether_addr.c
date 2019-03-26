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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <stdio.h>

#include <cryb/test.h>

#include "t_ether.h"

static struct t_ether_case {
	const char		*desc;
	const char		*str;
	size_t			 len;
	ether_addr		 addr;
} t_ether_cases[] = {
	{
		.desc	 = "empty",
		.str	 = "",
		.len	 = 0,
		.addr	 = { .o = { 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	 = "comma",
		.str	 = ",",
		.len	 = 0,
		.addr	 = { .o = { 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	 = "zero",
		.str	 = "00:00:00:00:00:00",
		.len	 = 17,
		.addr	 = { .o = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	},
	{
		.desc	 = "zero comma",
		.str	 = "00:00:00:00:00:00,",
		.len	 = 17,
		.addr	 = { .o = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
	},
	{
		.desc	 = "valid",
		.str	 = "02:00:18:11:09:02",
		.len	 = 17,
		.addr	 = { .o = { 0x02, 0x00, 0x18, 0x11, 0x09, 0x02 } },
	},
	{
		.desc	 = "dashes",
		.str	 = "02-00-18-11-09-02",
		.len	 = 17,
		.addr	 = { .o = { 0x02, 0x00, 0x18, 0x11, 0x09, 0x02 } },
	},
	{
		.desc	 = "mixed",
		.str	 = "02-00:18-11:09-02",
		.len	 = ~0U,
		.addr	 = { .o = { 0x02, 0x00, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	 = "broadcast",
		.str	 = "ff:ff:ff:ff:ff:ff",
		.len	 = 17,
		.addr	 = { .o = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	},
	{
		.desc	 = "BROADCAST",
		.str	 = "FF:FF:FF:FF:FF:FF",
		.len	 = 17,
		.addr	 = { .o = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	},
	{
		.desc	 = "BrOaDcAsT",
		.str	 = "Ff:fF:Ff:fF:Ff:fF",
		.len	 = 17,
		.addr	 = { .o = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
	},
	{
		.desc	= "garbage 1",
		.str	= "xyzzyx",
		.len	= 0,
		.addr	 = { .o = { 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	= "garbage 2",
		.str	= "0yzzyx",
		.len	= 0,
		.addr	 = { .o = { 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	= "garbage 3",
		.str	= "00zzyx",
		.len	= 0,
		.addr	 = { .o = { 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	= "garbage 4",
		.str	= "00:zyx",
		.len	= ~0U,
		.addr	 = { .o = { 0x00, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	= "garbage 5",
		.str	= "00:0yx",
		.len	= ~0U,
		.addr	 = { .o = { 0x00, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	= "garbage 6",
		.str	= "00:00x",
		.len	= ~0U,
		.addr	 = { .o = { 0x00, 0x00, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
	{
		.desc	= "garbage 7",
		.str	= "00:00-",
		.len	= ~0U,
		.addr	 = { .o = { 0x00, 0x00, 0xa5, 0xa5, 0xa5, 0xa5 } },
	},
};

static int
t_ether_addr(char **desc CRYB_UNUSED, void *arg)
{
	struct t_ether_case *t = arg;
	ether_addr addr;
	const char *e;
	int ret;

	addr = t_ether_cases[0].addr;
	e = ether_parse(t->str, &addr);
	if (t->len == ~0U) {
		ret = t_is_null(e);
	} else {
		ret = t_is_not_null(e);
		if (t->len > 0)
			ret &= t_compare_ptr(t->str + t->len, e);
	}
	ret &= t_compare_ether_addr(&t->addr, &addr);
	return (ret);
}

static int
t_prepare(int argc CRYB_UNUSED, char *argv[] CRYB_UNUSED)
{
	unsigned int i;

	for (i = 0; i < sizeof t_ether_cases / sizeof t_ether_cases[0]; ++i)
		t_add_test(t_ether_addr, &t_ether_cases[i],
		    "%s", t_ether_cases[i].desc);
	return (0);
}

int
main(int argc, char *argv[])
{

	t_main(t_prepare, NULL, argc, argv);
}
