/*-
 * Copyright (c) 2013-2016 The University of Oslo
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#define FC_LOGV_REQUIRED
#include <fc/log.h>

fc_log_level_t fc_log_level;

#if 0
static int
fc_log_level_to_syslog(fc_log_level_t level)
{

	switch (level) {
	case FC_LOG_LEVEL_DEBUG:
		return (LOG_DEBUG);
	case FC_LOG_LEVEL_VERBOSE:
		return (LOG_INFO);
	case FC_LOG_LEVEL_NOTICE:
		return (LOG_NOTICE);
	case FC_LOG_LEVEL_WARNING:
		return (LOG_WARNING);
	case FC_LOG_LEVEL_ERROR:
		return (LOG_ERR);
	default:
		return (LOG_INFO);
	}
}
#endif

static const char *
fc_log_level_to_string(fc_log_level_t level)
{

	switch (level) {
	case FC_LOG_LEVEL_DEBUG:
		return ("debug");
	case FC_LOG_LEVEL_VERBOSE:
		return ("verbose");
	case FC_LOG_LEVEL_NOTICE:
		return ("notice");
	case FC_LOG_LEVEL_WARNING:
		return ("warning");
	case FC_LOG_LEVEL_ERROR:
		return ("error");
	default:
		return ("unknown");
	}
}

void
fc_logv(fc_log_level_t level, const char *fmt, va_list ap)
{

	fprintf(stderr, "flycatcher: %s: ", fc_log_level_to_string(level));
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
}

/*
 * Log a message if at or above selected log level.
 */
void
fc_log(fc_log_level_t level, const char *fmt, ...)
{
	va_list ap;
	int serrno;

	serrno = errno;
	if (level >= fc_log_level) {
		va_start(ap, fmt);
		fc_logv(level, fmt, ap);
		va_end(ap);
	}
	errno = serrno;
}

void
fc_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fc_logv(FC_LOG_LEVEL_ERROR, fmt, ap);
	va_end(ap);
	exit(1);
}

/*
 * Specify a destination for log messages.  Passing NULL or an empty
 * string resets the log destination to stderr.
 */
int
fc_log_init(const char *ident, const char *logspec)
{

	(void)ident;
	(void)logspec;
	return (0);
}

/*
 * Close all log destinations
 */
int
fc_log_exit(void)
{

	return (0);
}
