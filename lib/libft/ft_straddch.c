/*-
 * Copyright (c) 2012 Dag-Erling Smørgrav
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

#include <errno.h>
#include <stdlib.h>

#include <ft/strutil.h>

#define MIN_STR_SIZE	32

/*
 * Add a character to a string, expanding the buffer if needed.
 */

int
ft_straddch(char **str, size_t *size, size_t *len, int ch)
{
	size_t tmpsize;
	char *tmpstr;

	if (*str == NULL) {
		/* initial allocation */
		tmpsize = MIN_STR_SIZE;
		if ((tmpstr = malloc(tmpsize)) == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		*str = tmpstr;
		*size = tmpsize;
		*len = 0;
	} else if (ch != 0 && *len + 1 >= *size) {
		/* additional space required */
		tmpsize = *size * 2;
		if ((tmpstr = realloc(*str, tmpsize)) == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		*size = tmpsize;
		*str = tmpstr;
	}
	if (ch != 0) {
		(*str)[*len] = ch;
		++*len;
	}
	(*str)[*len] = '\0';
	return (0);
}
