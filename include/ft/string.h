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

#ifndef FT_STRING_H_INCLUDED
#define FT_STRING_H_INCLUDED

#define string_new		ft_string_new
#define string_len		ft_string_len
#define string_buf		ft_string_buf
#define string_dup		ft_string_dup
#define string_dup_cs		ft_string_dup_cs
#define string_delete		ft_string_delete
#define string_expand		ft_string_expand
#define string_shrink		ft_string_shrink
#define string_trunc		ft_string_trunc
#define string_append_c		ft_string_append_c
#define string_append_cs	ft_string_append_cs
#define string_append_string	ft_string_append_string
#define string_printf		ft_string_printf
#define string_vprintf		ft_string_vprintf
#define string_compare		ft_string_compare
#define string_compare_cs	ft_string_compare_cs
#define string_equal		ft_string_equal
#define string_equal_cs		ft_string_equal_cs

typedef struct ft_string string;

string	*string_new(void);
size_t	 string_len(const string *);
const char *string_buf(const string *);
string	*string_dup(const string *);
string	*string_dup_cs(const char *, size_t);
void	 string_delete(string *);
int	 string_expand(string *, size_t);
void	 string_shrink(string *);
ssize_t	 string_trunc(string *, size_t);
ssize_t	 string_append_c(string *, char);
ssize_t	 string_append_cs(string *, const char *, size_t);
ssize_t	 string_append_string(string *, const string *, size_t);
ssize_t	 string_printf(string *, const char *, ...);
#ifdef va_start
ssize_t	 string_vprintf(string *, const char *, va_list);
#endif
int	 string_compare(const string *, const string *);
int	 string_compare_cs(const string *, const char *, size_t);
int	 string_equal(const string *, const string *);
int	 string_equal_cs(const string *, const char *, size_t);

#endif
