/*-
 * Copyright (c) 2012 Dag-Erling Smørgrav
 * Copyright (c) 2014-2015 The University of Oslo
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <fc/ctype.h>
#include "fc/strutil.h"

#define MIN_WORD_SIZE	32

/*
 * Read a word from a file, respecting shell quoting rules.
 */

char *
fc_readword(FILE *f, int *lineno, size_t *lenp)
{
	char *word;
	size_t size, len;
	int ch, escape, quote;
	int serrno;

	errno = 0;

	/* skip initial whitespace */
	escape = quote = 0;
	while ((ch = getc(f)) != EOF) {
		if (ch == '\n') {
			/* either EOL or line continuation */
			if (!escape)
				break;
			if (lineno != NULL)
				++*lineno;
			escape = 0;
		} else if (escape) {
			/* escaped something else */
			break;
		} else if (ch == '#') {
			/* comment: until EOL, no continuation */
			while ((ch = getc(f)) != EOF)
				if (ch == '\n')
					break;
			break;
		} else if (ch == '\\') {
			escape = 1;
		} else if (!is_ws(ch)) {
			break;
		}
	}
	if (ch == EOF)
		return (NULL);
	ungetc(ch, f);
	if (ch == '\n')
		return (NULL);

	word = NULL;
	size = len = 0;
	while ((ch = fgetc(f)) != EOF && (!is_ws(ch) || quote || escape)) {
		if (ch == '\\' && !escape && quote != '\'') {
			/* escape next character */
			escape = ch;
		} else if ((ch == '\'' || ch == '"') && !quote && !escape) {
			/* begin quote */
			quote = ch;
			/* edge case: empty quoted string */
			if (fc_straddch(&word, &size, &len, 0) != 0)
				return (NULL);
		} else if (ch == quote && !escape) {
			/* end quote */
			quote = 0;
		} else if (ch == '\n' && escape) {
			/* line continuation */
			escape = 0;
		} else {
			if (escape && quote && ch != '\\' && ch != quote &&
			    fc_straddch(&word, &size, &len, '\\') != 0) {
				free(word);
				errno = ENOMEM;
				return (NULL);
			}
			if (fc_straddch(&word, &size, &len, ch) != 0) {
				free(word);
				errno = ENOMEM;
				return (NULL);
			}
			escape = 0;
		}
		if (lineno != NULL && ch == '\n')
			++*lineno;
	}
	if (ch == EOF && ferror(f)) {
		serrno = errno;
		free(word);
		errno = serrno;
		return (NULL);
	}
	if (ch == EOF && (escape || quote)) {
		/* Missing escaped character or closing quote. */
		free(word);
		errno = EINVAL;
		return (NULL);
	}
	ungetc(ch, f);
	if (lenp != NULL)
		*lenp = len;
	return (word);
}
