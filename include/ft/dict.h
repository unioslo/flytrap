/*-
 * Copyright (c) 2014 The University of Oslo
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

#ifndef FT_DICT_H_INCLUDED
#define FT_DICT_H_INCLUDED

struct _ft_dict_ent { const char *key; void *value; };
struct ft_dict_ent;
struct ft_dict;

static inline const char *
ft_dict_key(struct ft_dict_ent *e)
{

	return (((struct _ft_dict_ent *)e)->key);
}

static inline const void *
ft_dict_value(struct ft_dict_ent *e)
{

	return (((struct _ft_dict_ent *)e)->value);
}

struct ft_dict *ft_dict_create(void);
void ft_dict_destroy(struct ft_dict *);
int ft_dict_insert(struct ft_dict *, const char *, void *);
int ft_dict_remove(struct ft_dict *, const char *);
const struct ft_dict_ent *ft_dict_first(const struct ft_dict *);
const struct ft_dict_ent *ft_dict_next(const struct ft_dict *,
    const struct ft_dict_ent *);

#endif
