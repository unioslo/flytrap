/*-
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

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ft/dict.h>
#include <ft/hash.h>

struct ft_dict_ent {
	const char		*key;
	void			*value;
	unsigned int		 h;
	struct ft_dict_ent	*next;
};

struct ft_dict {
	struct ft_dict_ent	*entries[256];
	unsigned int		 nentries;
};

/*
 * Create a dictionary
 */
struct ft_dict *
ft_dict_create(void)
{
	struct ft_dict *d;

	/* allocate */
	if ((d = calloc(1, sizeof *d)) == NULL)
		return (NULL);
	return (d);
}

/*
 * Destroy a dictionary
 */
void
ft_dict_destroy(struct ft_dict *d)
{
	struct ft_dict_ent *e;
	unsigned int h;

	for (h = 0; h < sizeof d->entries / sizeof *d->entries; ++h) {
		while (d->entries[h] != NULL) {
			e = d->entries[h];
			d->entries[h] = e->next;
			free(e);
		}
	}
	free(d);
}

/*
 * Add an entry to a dictionary
 */
int
ft_dict_insert(struct ft_dict *d, const char *key, void *value)
{
	struct ft_dict_ent **epp;
	unsigned int h;

	h = ft_strhash(key);
	assert(h < sizeof d->entries / sizeof *d->entries);
	for (epp = &d->entries[h]; *epp != NULL; epp = &(*epp)->next) {
		assert((*epp)->h == h);
		if (strcmp((*epp)->key, key) == 0) {
			errno = EEXIST;
			return (-1);
		}
	}
	if ((*epp = calloc(1, sizeof **epp)) == NULL)
		return (-1);
	(*epp)->key = key;
	(*epp)->h = h;
	(*epp)->value = value;
	d->nentries++;
	return (0);
}

/*
 * Remove an entry from a dictionary
 */
int
ft_dict_remove(struct ft_dict *d, const char *key)
{
	struct ft_dict_ent *ep, **epp;
	unsigned int h;

	h = ft_strhash(key);
	assert(h < sizeof d->entries / sizeof *d->entries);
	for (epp = &d->entries[h]; *epp != NULL; epp = &(*epp)->next) {
		assert((*epp)->h == h);
		if (strcmp((*epp)->key, key) == 0) {
			ep = *epp;
			*epp = ep->next;
			free(ep);
			d->nentries--;
			return (0);
		}
	}
	errno = ENOENT;
	return (-1);
}

/*
 * Iterate over a dictionary: first entry
 */
const struct ft_dict_ent *
ft_dict_first(const struct ft_dict *d)
{
	unsigned int h;

	for (h = 0; h < sizeof d->entries / sizeof *d->entries; ++h) {
		if (d->entries[h] != NULL) {
			assert(d->entries[h]->h == h);
			return (d->entries[h]);
		}
	}
	return (NULL);
}

/*
 * Iterate over a dictionary: next entry
 */
const struct ft_dict_ent *
ft_dict_next(const struct ft_dict *d, const struct ft_dict_ent *e)
{
	unsigned int h;

	if (e == NULL)
		return (ft_dict_first(d));
	assert(e->h < sizeof d->entries / sizeof *d->entries);
	if (e->next != NULL)
		return (e->next);
	for (h = e->h + 1; h < sizeof d->entries / sizeof *d->entries; ++h) {
		if (d->entries[h] != NULL) {
			assert(d->entries[h]->h == h);
			return (d->entries[h]);
		}
	}
	return (NULL);
}
