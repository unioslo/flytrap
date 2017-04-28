/*-
 * Copyright (c) 2014-2016 Dag-Erling Smørgrav
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

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <ft/string.h>

#include <cryb/test.h>

#define char_t			char

#define CS(lit)			lit

#define T_MAGIC_STR		CS("xyzzy")
#define T_MAGIC_LEN		(sizeof("xyzzy") - 1)
#define T_LONG_MAGIC_STR	CS("squeamish ossifrage")
#define T_LONG_MAGIC_LEN	(sizeof("squeamish ossifrage") - 1)

static int
t_string_noop(char **desc CRYB_UNUSED, void *arg)
{
	string *str;

	(void)arg;
	if ((str = string_new()) == NULL)
		return (0);
	string_delete(str);
	return (1);
}

static int
t_string_new(char **desc CRYB_UNUSED, void *arg CRYB_UNUSED)
{
	string *s;
	int ret;

	ret = 1;
	t_malloc_fail_after = 1;
	ret &= t_is_not_null(s = string_new());
	string_delete(s);
	ret &= t_is_null(s = string_new());
	string_delete(s);
	t_malloc_fail = 0;
	return (ret);
}


/***************************************************************************
 * Appending and expansion
 */

static struct t_append_case {
	const char *desc;
	const char_t *s;
	size_t ilen;
	ssize_t olen;
	int fail;
} t_append_cases[] = {
	/* all short cases are performed with malloc failure enabled */
	{
		.desc	 = "empty with limit",
		.s	 = CS(""),
		.ilen	 = 0,
		.olen	 = 0,
		.fail	 = 1,
	},
	{
		.desc	 = "empty without limit",
		.s	 = CS(""),
		.ilen	 = SIZE_MAX,
		.olen	 = 0,
		.fail	 = 1,
	},
	{
		.desc	 = "short with limit",
		.s	 = T_MAGIC_STR,
		.ilen	 = T_MAGIC_LEN / 2,
		.olen	 = T_MAGIC_LEN / 2,
		.fail	 = 1,
	},
	{
		.desc	 = "short without limit",
		.s	 = T_MAGIC_STR,
		.ilen	 = SIZE_MAX,
		.olen	 = T_MAGIC_LEN,
		.fail	 = 1,
	},
	/* expected to allocate (but we have no way to test that) */
	{
		.desc	 = "long",
		.s	 = T_LONG_MAGIC_STR,
		.ilen	 = SIZE_MAX,
		.olen	 = T_LONG_MAGIC_LEN,
		.fail	 = 0,
	},
	/* expected to try to allocate and fail */
	{
		.desc	 = "long with allocation failure",
		.s	 = T_LONG_MAGIC_STR,
		.ilen	 = SIZE_MAX,
		.olen	 = -1,
		.fail	 = 1,
	},
};

static int
t_string_append_cs(char **desc CRYB_UNUSED, void *arg)
{
	struct t_append_case *t = arg;
	string *s;
	int ret;

	s = string_new();
	t_malloc_fail = t->fail;
	ret = t_compare_ssz(t->olen, string_append_cs(s, t->s, t->ilen));
	t_malloc_fail = 0;
	string_delete(s);
	return (ret);
}

static int
t_string_append_string(char **desc CRYB_UNUSED, void *arg)
{
	struct t_append_case *t = arg;
	string *s, *os;
	int ret;

	s = string_new();
	string_append_cs(s, CS("!"), 1);
	os = string_dup_cs(t->s, SIZE_MAX);
	t_malloc_fail = t->fail;
	ret = t_compare_ssz(t->olen < 0 ? t->olen : t->olen + 1,
	    string_append_string(s, os, t->ilen));
	t_malloc_fail = 0;
	string_delete(os);
	string_delete(s);
	return (ret);
}


/***************************************************************************
 * Buffers and lengths
 */

static struct t_buf_case {
	const char *desc;
	const char_t *s;
	size_t len;
} t_buf_cases[] = {
	{
		.desc	 = "empty",
		.s	 = CS(""),
		.len	 = 0,
	},
	{
		.desc	 = "one",
		.s	 = CS("1"),
		.len	 = 1,
	},
	{
		.desc	 = "short",
		.s	 = T_MAGIC_STR,
		.len	 = T_MAGIC_LEN,
	},
	{
		.desc	 = "long",
		.s	 = T_LONG_MAGIC_STR,
		.len	 = T_LONG_MAGIC_LEN,
	},
};

static int
t_string_buf(char **desc CRYB_UNUSED, void *arg)
{
	struct t_buf_case *t = arg;
	const char_t *buf;
	string *s;
	int ret;

	ret = 1;
	s = string_dup_cs(t->s, t->len);
	buf = string_buf(s);
	ret &= t_compare_mem(t->s, buf, (t->len + 1) * sizeof(char_t));
	string_append_cs(s, t->s, t->len);
	buf = string_buf(s);
	ret &= t_compare_mem(t->s, buf, t->len * sizeof(char_t)) &
	    t_compare_mem(t->s, buf + t->len, (t->len + 1) * sizeof(char_t));
	string_delete(s);
	return (ret);
}

static int
t_string_len(char **desc CRYB_UNUSED, void *arg)
{
	struct t_buf_case *t = arg;
	string *s;
	int ret;

	ret = 1;
	s = string_dup_cs(t->s, t->len);
	ret = t_compare_i(t->len, string_len(s));
	string_append_cs(s, t->s, t->len);
	ret &= t_compare_i(t->len + t->len, string_len(s));
	string_delete(s);
	return (ret);
}


/***************************************************************************
 * Comparisons
 */

static struct t_compare_case {
	const char *desc;
	const char_t *s1, *s2;
	int cmp;
} t_compare_cases[] = {
	{
		"empty with empty",
		CS(""),
		CS(""),
		0,
	},
	{
		"empty with non-empty",
		CS(""),
		CS("xyzzy"),
		-1,
	},
	{
		"non-empty with empty",
		CS("xyzzy"),
		CS(""),
		1,
	},
	{
		"non-empty with same non-empty",
		CS("xyzzy"),
		CS("xyzzy"),
		0,
	},
	{
		"non-empty with later non-empty",
		CS("abba"),
		CS("baba"),
		-1,
	},
	{
		"non-empty with earlier non-empty",
		CS("baba"),
		CS("abba"),
		1,
	},
	{
		"non-empty prefix with non-empty",
		CS("baba"),
		CS("babaorum"),
		-1,
	},
	{
		"non-empty with non-empty prefix",
		CS("babaorum"),
		CS("baba"),
		1,
	},
};

static int
t_string_compare(char **desc CRYB_UNUSED, void *arg)
{
	struct t_compare_case *t = arg;
	string *s1, *s2;
	int ret;

	s1 = string_dup_cs(t->s1, SIZE_MAX);
	s2 = string_dup_cs(t->s2, SIZE_MAX);
	ret = t_compare_i(t->cmp, string_compare(s1, s2));
	string_delete(s2);
	string_delete(s1);
	return (ret);
}

static int
t_string_compare_cs(char **desc CRYB_UNUSED, void *arg)
{
	struct t_compare_case *t = arg;
	string *s1;
	int ret;

	s1 = string_dup_cs(t->s1, SIZE_MAX);
	ret = t_compare_i(t->cmp, string_compare_cs(s1, t->s2, SIZE_MAX));
	string_delete(s1);
	return (ret);
}

static int
t_string_equal(char **desc CRYB_UNUSED, void *arg)
{
	struct t_compare_case *t = arg;
	string *s1, *s2;
	int ret = 1;

	s1 = string_dup_cs(t->s1, SIZE_MAX);
	s2 = string_dup_cs(t->s2, SIZE_MAX);
	ret = t_compare_i(!!t->cmp, string_equal(s1, s2) == 0);
	string_delete(s2);
	string_delete(s1);
	return (ret);
}

static int
t_string_equal_cs(char **desc CRYB_UNUSED, void *arg)
{
	struct t_compare_case *t = arg;
	string *s1;
	int ret = 1;

	s1 = string_dup_cs(t->s1, SIZE_MAX);
	ret = t_compare_i(!!t->cmp, string_equal_cs(s1, t->s2, SIZE_MAX) == 0);
	string_delete(s1);
	return (ret);
}


/***************************************************************************
 * Miscellaneous functions
 */

static int
t_string_trunc(char **desc CRYB_UNUSED, void *arg CRYB_UNUSED)
{
	string *s;
	ssize_t len;
	int ret;

	s = string_dup_cs(T_MAGIC_STR, SIZE_MAX);
	len = string_len(s);
	ret = t_compare_ssz(T_MAGIC_LEN, len) &
	    t_compare_ssz(len, string_trunc(s, SIZE_MAX)) &
	    t_compare_ssz(len, string_trunc(s, len + 1)) &
	    t_compare_ssz(len, string_trunc(s, len)) &
	    t_compare_ssz(len - 1, string_trunc(s, len - 1));
	string_delete(s);
	return (ret);
}


/***************************************************************************
 * Boilerplate
 */

static int
t_prepare(int argc, char *argv[])
{
	unsigned int i;

	(void)argc;
	(void)argv;

	t_malloc_fatal = 1;
	t_add_test(t_string_noop, NULL, "no-op");
	t_add_test(t_string_new, NULL, "string_new");
	for (i = 0; i < sizeof t_append_cases / sizeof *t_append_cases; ++i)
		t_add_test(t_string_append_cs, &t_append_cases[i],
		    "%s (%s)", "string_append_cs", t_append_cases[i].desc);
	for (i = 0; i < sizeof t_append_cases / sizeof *t_append_cases; ++i)
		t_add_test(t_string_append_string, &t_append_cases[i],
		    "%s (%s)", "string_append_string", t_append_cases[i].desc);
	for (i = 0; i < sizeof t_buf_cases / sizeof *t_buf_cases; ++i)
		t_add_test(t_string_len, &t_buf_cases[i],
		    "%s (%s)", "string_len", t_buf_cases[i].desc);
	for (i = 0; i < sizeof t_buf_cases / sizeof *t_buf_cases; ++i)
		t_add_test(t_string_buf, &t_buf_cases[i],
		    "%s (%s)", "string_buf", t_buf_cases[i].desc);
	// t_add_test(t_string_dup_cs, NULL, "string_dup_cs");
	for (i = 0; i < sizeof t_compare_cases / sizeof *t_compare_cases; ++i) {
		t_add_test(t_string_compare, &t_compare_cases[i],
		    "%s (%s)", "string_compare", t_compare_cases[i].desc);
		t_add_test(t_string_compare_cs, &t_compare_cases[i],
		    "%s (%s)", "string_compare_cs", t_compare_cases[i].desc);
	}
	for (i = 0; i < sizeof t_compare_cases / sizeof *t_compare_cases; ++i) {
		t_add_test(t_string_equal, &t_compare_cases[i],
		    "%s (%s)", "string_equal", t_compare_cases[i].desc);
		t_add_test(t_string_equal_cs, &t_compare_cases[i],
		    "%s (%s)", "string_equal_cs", t_compare_cases[i].desc);
	}
	t_add_test(t_string_trunc, NULL, "string_trunc");
	return (0);
}

int
main(int argc, char *argv[])
{

	t_main(t_prepare, NULL, argc, argv);
}
