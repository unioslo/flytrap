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

#include <sys/time.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <ft/ethernet.h>
#include <ft/ip4.h>

#include "flytrap.h"
#include "ethernet.h"

static FILE *csvfile;

int
csv_packet4(const struct timeval *tv,
    const ip4_addr *sa, int sp,
    const ip4_addr *da, int dp,
    const char *proto, size_t len, const char *fmt, ...)
{
	va_list ap;

	fprintf(csvfile,
	    "%llu.%06lu,%d.%d.%d.%d,%d,%d.%d.%d.%d,%d,%s,%zu,",
	    (unsigned long long)tv->tv_sec, (unsigned long)tv->tv_usec,
	    sa->o[0], sa->o[1], sa->o[2], sa->o[3], sp,
	    da->o[0], da->o[1], da->o[2], da->o[3], dp,
	    proto, len);
	va_start(ap, fmt);
	vfprintf(csvfile ? csvfile : stdout, fmt, ap);
	va_end(ap);
	fprintf(csvfile ? csvfile : stdout, "\n");
	fflush(csvfile);
	return (0);
}

int
csv_open(const char *csvfn)
{
	FILE *nf, *of;

	if (csvfn == NULL)
		nf = stdout;
	else if ((nf = fopen(csvfn, "a")) == NULL)
		return (-1);
	of = csvfile;
	csvfile = nf;
	if (of != NULL && of != stdout)
		fclose(of);
	return (0);
}
