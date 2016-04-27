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

#ifndef FC_LOG_H_INCLUDED
#define FC_LOG_H_INCLUDED

typedef enum {
	FC_LOG_LEVEL_DEBUG,
	FC_LOG_LEVEL_VERBOSE,
	FC_LOG_LEVEL_NOTICE,
	FC_LOG_LEVEL_WARNING,
	FC_LOG_LEVEL_ERROR,
	FC_LOG_LEVEL_MAX
} fc_log_level_t;

#ifdef FC_LOGV_REQUIRED
void fc_logv(fc_log_level_t, const char *, va_list);
#endif
void fc_log(fc_log_level_t, const char *, ...);
int fc_log_init(const char *, const char *);
int fc_log_exit(void);

extern fc_log_level_t fc_log_level;

#define fc_debug(...)							\
	fc_log(FC_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define fc_verbose(...)							\
	fc_log(FC_LOG_LEVEL_VERBOSE, __VA_ARGS__)
#define fc_notice(...)							\
	fc_log(FC_LOG_LEVEL_NOTICE, __VA_ARGS__)
#define fc_warning(...)							\
	fc_log(FC_LOG_LEVEL_WARNING, __VA_ARGS__)
#define fc_error(...)							\
	fc_log(FC_LOG_LEVEL_ERROR, __VA_ARGS__)
#define fc_fatal(...)							\
	fc_fatal(__VA_ARGS__)

#endif
