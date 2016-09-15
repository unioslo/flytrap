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

#ifndef FT_LOG_H_INCLUDED
#define FT_LOG_H_INCLUDED

typedef enum {
	FT_LOG_LEVEL_DEBUG,
	FT_LOG_LEVEL_VERBOSE,
	FT_LOG_LEVEL_NOTICE,
	FT_LOG_LEVEL_WARNING,
	FT_LOG_LEVEL_ERROR,
	FT_LOG_LEVEL_MAX
} ft_log_level_t;

#ifdef FT_LOGV_REQUIRED
void ft_logv(ft_log_level_t, const char *, va_list);
#endif
void ft_log(ft_log_level_t, const char *, ...);
void ft_fatal(const char *, ...);
int ft_log_init(const char *, const char *);
int ft_log_exit(void);

extern ft_log_level_t ft_log_level;

#define ft_log_if(level, ...)						\
	do {								\
		if (level >= ft_log_level)				\
			ft_log(level, __VA_ARGS__);			\
	} while (0)
#define ft_debug(...)							\
	ft_log_if(FT_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define ft_verbose(...)							\
	ft_log_if(FT_LOG_LEVEL_VERBOSE, __VA_ARGS__)
#define ft_notice(...)							\
	ft_log_if(FT_LOG_LEVEL_NOTICE, __VA_ARGS__)
#define ft_warning(...)							\
	ft_log_if(FT_LOG_LEVEL_WARNING, __VA_ARGS__)
#define ft_error(...)							\
	ft_log_if(FT_LOG_LEVEL_ERROR, __VA_ARGS__)
#define ft_fatal(...)							\
	ft_fatal(__VA_ARGS__)

#endif
