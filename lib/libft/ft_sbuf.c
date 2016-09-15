/*-
 * Copyright (c) 2000-2008 Poul-Henning Kamp
 * Copyright (c) 2000-2008 Dag-Erling Smørgrav
 * Copyright (c) 2014 The University of Oslo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ft/sbuf.h>

#define	KASSERT(e, m)		assert(e)
#define	SBMALLOC(size)		malloc(size)
#define	SBFREE(buf)		free(buf)

#define	roundup2(x, y)	(((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */

/*
 * Predicates
 */
#define	SBUF_ISDYNAMIC(s)	((s)->s_flags & SBUF_DYNAMIC)
#define	SBUF_ISDYNSTRUCT(s)	((s)->s_flags & SBUF_DYNSTRUCT)
#define	SBUF_ISFINISHED(s)	((s)->s_flags & SBUF_FINISHED)
#define	SBUF_HASROOM(s)		((s)->s_len < (s)->s_size - 1)
#define	SBUF_FREESPACE(s)	((s)->s_size - ((s)->s_len + 1))
#define	SBUF_CANEXTEND(s)	((s)->s_flags & SBUF_AUTOEXTEND)

/*
 * Set / clear flags
 */
#define	SBUF_SETFLAG(s, f)	do { (s)->s_flags |= (f); } while (0)
#define	SBUF_CLEARFLAG(s, f)	do { (s)->s_flags &= ~(f); } while (0)

#define	SBUF_MINEXTENDSIZE	16		/* Should be power of 2. */

#ifdef PAGE_SIZE
#define	SBUF_MAXEXTENDSIZE	PAGE_SIZE
#define	SBUF_MAXEXTENDINCR	PAGE_SIZE
#else
#define	SBUF_MAXEXTENDSIZE	4096
#define	SBUF_MAXEXTENDINCR	4096
#endif

/*
 * Debugging support
 */
#if !defined(NDEBUG)
static void
_assert_sbuf_integrity(const char *fun, const struct sbuf *s)
{

	(void)fun;
	(void)s;
	KASSERT(s != NULL,
	    ("%s called with a NULL sbuf pointer", fun));
	KASSERT(s->magic == SBUF_MAGIC,
	    ("%s called wih an bogus sbuf pointer", fun));
	KASSERT(s->s_buf != NULL,
	    ("%s called with uninitialized or corrupt sbuf", fun));
	KASSERT(s->s_len < s->s_size,
	    ("wrote past end of sbuf (%d >= %d)", s->s_len, s->s_size));
}

static void
_assert_sbuf_state(const char *fun, const struct sbuf *s, int state)
{

	(void)fun;
	(void)s;
	(void)state;
	KASSERT((s->s_flags & SBUF_FINISHED) == state,
	    ("%s called with %sfinished or corrupt sbuf", fun,
	    (state ? "un" : "")));
}
#define	assert_sbuf_integrity(s) _assert_sbuf_integrity(__func__, (s))
#define	assert_sbuf_state(s, i)	 _assert_sbuf_state(__func__, (s), (i))
#else
#define	assert_sbuf_integrity(s) do { } while (0)
#define	assert_sbuf_state(s, i)	 do { } while (0)
#endif

#ifdef CTASSERT
CTASSERT(powerof2(SBUF_MAXEXTENDSIZE));
CTASSERT(powerof2(SBUF_MAXEXTENDINCR));
#endif


static int
sbuf_extendsize(int size)
{
	int newsize;

	if (size < (int)SBUF_MAXEXTENDSIZE) {
		newsize = SBUF_MINEXTENDSIZE;
		while (newsize < size)
			newsize *= 2;
	} else {
		newsize = roundup2(size, SBUF_MAXEXTENDINCR);
	}
	KASSERT(newsize >= size, ("%s: %d < %d\n", __func__, newsize, size));
	return (newsize);
}

/*
 * Extend an sbuf.
 */
static int
sbuf_extend(struct sbuf *s, int addlen)
{
	char *newbuf;
	int newsize;

	if (!SBUF_CANEXTEND(s))
		return (-1);
	newsize = sbuf_extendsize(s->s_size + addlen);
	newbuf = SBMALLOC(newsize);
	if (newbuf == NULL)
		return (-1);
	memcpy(newbuf, s->s_buf, s->s_size);
	if (SBUF_ISDYNAMIC(s))
		SBFREE(s->s_buf);
	else
		SBUF_SETFLAG(s, SBUF_DYNAMIC);
	s->s_buf = newbuf;
	s->s_size = newsize;
	return (0);
}

/*
 * Initialize the internals of an sbuf.
 * If buf is non-NULL, it points to a static or already-allocated string
 * big enough to hold at least length characters.
 */
static struct sbuf *
sbuf_newbuf(struct sbuf *s, char *buf, int length, int flags)
{

	memset(s, 0, sizeof(*s));
	s->magic = SBUF_MAGIC;
	s->s_flags = flags;
	s->s_size = length;
	s->s_buf = buf;

	if ((s->s_flags & SBUF_AUTOEXTEND) == 0) {
		KASSERT(s->s_size > 1,
		    ("attempt to create a too small sbuf"));
	}

	if (s->s_buf != NULL)
		return (s);

	if ((flags & SBUF_AUTOEXTEND) != 0)
		s->s_size = sbuf_extendsize(s->s_size);

	s->s_buf = SBMALLOC(s->s_size);
	if (s->s_buf == NULL)
		return (NULL);
	SBUF_SETFLAG(s, SBUF_DYNAMIC);
	return (s);
}

/*
 * Initialize an sbuf.
 * If buf is non-NULL, it points to a static or already-allocated string
 * big enough to hold at least length characters.
 */
struct sbuf *
sbuf_new(struct sbuf *s, char *buf, int length, int flags)
{

	KASSERT(length >= 0,
	    ("attempt to create an sbuf of negative length (%d)", length));
	KASSERT((flags & ~SBUF_USRFLAGMSK) == 0,
	    ("%s called with invalid flags", __func__));

	flags &= SBUF_USRFLAGMSK;
	if (s != NULL)
		return (sbuf_newbuf(s, buf, length, flags));

	s = SBMALLOC(sizeof(*s));
	if (s == NULL)
		return (NULL);
	if (sbuf_newbuf(s, buf, length, flags) == NULL) {
		SBFREE(s);
		return (NULL);
	}
	SBUF_SETFLAG(s, SBUF_DYNSTRUCT);
	return (s);
}

/*
 * Clear an sbuf and reset its position.
 */
void
sbuf_clear(struct sbuf *s)
{

	assert_sbuf_integrity(s);
	/* don't care if it's finished or not */

	SBUF_CLEARFLAG(s, SBUF_FINISHED);
	s->s_error = 0;
	s->s_len = 0;
}

/*
 * Set the sbuf's end position to an arbitrary value.
 * Effectively truncates the sbuf at the new position.
 */
int
sbuf_setpos(struct sbuf *s, ssize_t pos)
{

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	KASSERT(pos >= 0,
	    ("attempt to seek to a negative position (%jd)", (intmax_t)pos));
	KASSERT(pos < s->s_size,
	    ("attempt to seek past end of sbuf (%jd >= %jd)",
	    (intmax_t)pos, (intmax_t)s->s_size));

	if (pos < 0 || pos > s->s_len)
		return (-1);
	s->s_len = pos;
	return (0);
}

/*
 * Append a byte to an sbuf.  This is the core function for appending
 * to an sbuf and is the main place that deals with extending the
 * buffer and marking overflow.
 */
static void
sbuf_put_byte(struct sbuf *s, int c)
{

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	if (s->s_error != 0)
		return;
	if (SBUF_FREESPACE(s) <= 0) {
		if (sbuf_extend(s, 1) < 0)
			s->s_error = ENOMEM;
		if (s->s_error != 0)
			return;
	}
	s->s_buf[s->s_len++] = (char)c;
}

/*
 * Append a byte string to an sbuf.
 */
int
sbuf_bcat(struct sbuf *s, const void *buf, size_t len)
{
	const char *str = buf;
	const char *end = str + len;

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	if (s->s_error != 0)
		return (-1);
	for (; str < end; str++) {
		sbuf_put_byte(s, *str);
		if (s->s_error != 0)
			return (-1);
	}
	return (0);
}

/*
 * Copy a byte string into an sbuf.
 */
int
sbuf_bcpy(struct sbuf *s, const void *buf, size_t len)
{

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	sbuf_clear(s);
	return (sbuf_bcat(s, buf, len));
}

/*
 * Append a string to an sbuf.
 */
int
sbuf_cat(struct sbuf *s, const char *str)
{

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	if (s->s_error != 0)
		return (-1);

	while (*str != '\0') {
		sbuf_put_byte(s, *str++);
		if (s->s_error != 0)
			return (-1);
	}
	return (0);
}

/*
 * Copy a string into an sbuf.
 */
int
sbuf_cpy(struct sbuf *s, const char *str)
{

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	sbuf_clear(s);
	return (sbuf_cat(s, str));
}

/*
 * Format the given argument list and append the resulting string to an sbuf.
 */
int
sbuf_vprintf(struct sbuf *s, const char *fmt, va_list ap)
{
	va_list ap_copy;
	int len;

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	KASSERT(fmt != NULL,
	    ("%s called with a NULL format string", __func__));

	if (s->s_error != 0)
		return (-1);

	/*
	 * For the moment, there is no way to get vsnprintf(3) to hand
	 * back a character at a time, to push everything into
	 * sbuf_putc_func() as was done for the kernel.
	 *
	 * In userspace, while drains are useful, there's generally
	 * not a problem attempting to malloc(3) on out of space.  So
	 * expand a userland sbuf if there is not enough room for the
	 * data produced by SBUF_[v]printf(3).
	 */

	do {
		va_copy(ap_copy, ap);
		len = vsnprintf(&s->s_buf[s->s_len], SBUF_FREESPACE(s) + 1,
		    fmt, ap_copy);
		va_end(ap_copy);
	} while (len > SBUF_FREESPACE(s) &&
	    sbuf_extend(s, len - SBUF_FREESPACE(s)) == 0);

	/*
	 * s->s_len is the length of the string, without the terminating nul.
	 * When updating s->s_len, we must subtract 1 from the length that
	 * we passed into vsnprintf() because that length includes the
	 * terminating nul.
	 *
	 * vsnprintf() returns the amount that would have been copied,
	 * given sufficient space, so don't over-increment s_len.
	 */
	if (SBUF_FREESPACE(s) < len)
		len = SBUF_FREESPACE(s);
	s->s_len += len;
	if (!SBUF_HASROOM(s) && !SBUF_CANEXTEND(s))
		s->s_error = ENOMEM;

	KASSERT(s->s_len < s->s_size,
	    ("wrote past end of sbuf (%d >= %d)", s->s_len, s->s_size));

	if (s->s_error != 0)
		return (-1);
	return (0);
}

/*
 * Format the given arguments and append the resulting string to an sbuf.
 */
int
sbuf_printf(struct sbuf *s, const char *fmt, ...)
{
	va_list ap;
	int result;

	va_start(ap, fmt);
	result = sbuf_vprintf(s, fmt, ap);
	va_end(ap);
	return (result);
}

/*
 * Append a character to an sbuf.
 */
int
sbuf_putc(struct sbuf *s, int c)
{

	sbuf_put_byte(s, c);
	if (s->s_error != 0)
		return (-1);
	return (0);
}

/*
 * Trim whitespace characters from end of an sbuf.
 */
int
sbuf_trim(struct sbuf *s)
{

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	if (s->s_error != 0)
		return (-1);

	while (s->s_len > 0 && isspace(s->s_buf[s->s_len-1]))
		--s->s_len;

	return (0);
}

/*
 * Check if an sbuf has an error.
 */
int
sbuf_error(const struct sbuf *s)
{

	return (s->s_error);
}

/*
 * Finish off an sbuf.
 */
int
sbuf_finish(struct sbuf *s)
{

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, 0);

	s->s_buf[s->s_len] = '\0';
	SBUF_SETFLAG(s, SBUF_FINISHED);
	errno = s->s_error;
	if (s->s_error)
		return (-1);
	return (0);
}

/*
 * Return a pointer to the sbuf data.
 */
char *
sbuf_data(const struct sbuf *s)
{

	assert_sbuf_integrity(s);
	assert_sbuf_state(s, SBUF_FINISHED);

	return (s->s_buf);
}

/*
 * Return the length of the sbuf data.
 */
ssize_t
sbuf_len(const struct sbuf *s)
{

	assert_sbuf_integrity(s);
	/* don't care if it's finished or not */

	if (s->s_error != 0)
		return (-1);
	return (s->s_len);
}

/*
 * Clear an sbuf, free its buffer if necessary.
 */
void
sbuf_delete(struct sbuf *s)
{
	int isdyn;

	assert_sbuf_integrity(s);
	/* don't care if it's finished or not */

	if (SBUF_ISDYNAMIC(s))
		SBFREE(s->s_buf);
	isdyn = SBUF_ISDYNSTRUCT(s);
	memset(s, 0, sizeof(*s));
	if (isdyn)
		SBFREE(s);
}

/*
 * Check if an sbuf has been finished.
 */
int
sbuf_done(const struct sbuf *s)
{

	return(SBUF_ISFINISHED(s));
}

/*
 * Quote a string
 */
void
sbuf_quote(struct sbuf *s, const char *p, int len, int how)
{
	const char *q;
	int quote = 0;

	(void)how;	/* For future enhancements */
	if (len == -1)
		len = strlen(p);

	for (q = p; q < p + len; q++) {
		if (!isgraph(*q) || *q == '"' || *q == '\\') {
			quote++;
			break;
		}
	}
	if (!quote) {
		(void)sbuf_bcat(s, p, len);
		return;
	}
	(void)sbuf_putc(s, '"');
	for (q = p; q < p + len; q++) {
		switch (*q) {
		case ' ':
			(void)sbuf_putc(s, *q);
			break;
		case '\\':
		case '"':
			(void)sbuf_putc(s, '\\');
			(void)sbuf_putc(s, *q);
			break;
		case '\n':
			(void)sbuf_cat(s, "\\n");
			break;
		case '\r':
			(void)sbuf_cat(s, "\\r");
			break;
		case '\t':
			(void)sbuf_cat(s, "\\t");
			break;
		default:
			if (isgraph(*q))
				(void)sbuf_putc(s, *q);
			else
				(void)sbuf_printf(s, "\\%o", *q & 0xff);
			break;
		}
	}
	(void)sbuf_putc(s, '"');
}

/*
 * Unquote a string
 */
const char *
sbuf_unquote(struct sbuf *s, const char *p, int len, int how)
{
	const char *q;
	char *r;
	unsigned long u;
	char c;

	(void)how;	/* For future enhancements */

	if (len == -1)
		len = strlen(p);

	for (q = p; q < p + len; q++) {
		if (*q != '\\') {
			(void)sbuf_bcat(s, q, 1);
			continue;
		}
		if (++q >= p + len)
			return ("Incomplete '\\'-sequence at end of string");

		switch(*q) {
		case 'n':
			(void)sbuf_bcat(s, "\n", 1);
			continue;
		case 'r':
			(void)sbuf_bcat(s, "\r", 1);
			continue;
		case 't':
			(void)sbuf_bcat(s, "\t", 1);
			continue;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			errno = 0;
			u = strtoul(q, &r, 8);
			if (errno != 0 || (u & ~0xff))
				return ("\\ooo sequence out of range");
			c = (char)u;
			(void)sbuf_bcat(s, &c, 1);
			q = r - 1;
			continue;
		default:
			(void)sbuf_bcat(s, q, 1);
		}
	}
	return (NULL);
}
