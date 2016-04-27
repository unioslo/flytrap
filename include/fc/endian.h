/*-
 * Copyright (c) 2014 Dag-Erling Smørgrav
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

#ifndef FC_ENDIAN_H_INCLUDED
#define FC_ENDIAN_H_INCLUDED

#if HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#if HAVE_ENDIAN_H
#include <endian.h>
#endif

#if !HAVE_DECL_BE16ENC
#define be16enc fc_be16enc
#endif
#if !HAVE_DECL_BE16DEC
#define be16dec fc_be16dec
#endif
#if !HAVE_DECL_BE32ENC
#define be32enc fc_be32enc
#endif
#if !HAVE_DECL_BE32DEC
#define be32dec fc_be32dec
#endif
#if !HAVE_DECL_BE64ENC
#define be64enc fc_be64enc
#endif
#if !HAVE_DECL_BE64DEC
#define be64dec fc_be64dec
#endif
#if !HAVE_DECL_LE16ENC
#define le16enc fc_le16enc
#endif
#if !HAVE_DECL_LE16DEC
#define le16dec fc_le16dec
#endif
#if !HAVE_DECL_LE32ENC
#define le32enc fc_le32enc
#endif
#if !HAVE_DECL_LE32DEC
#define le32dec fc_le32dec
#endif
#if !HAVE_DECL_LE64ENC
#define le64enc fc_le64enc
#endif
#if !HAVE_DECL_LE64DEC
#define le64dec fc_le64dec
#endif

static inline void
fc_be16enc(void *p, uint16_t u16)
{
	((uint8_t *)p)[1] = u16 & 0xff;
	((uint8_t *)p)[0] = (u16 >> 8) & 0xff;
}

static inline uint16_t
fc_be16dec(const void *p)
{
	return ((uint16_t)((const uint8_t *)p)[1] |
	    (uint16_t)((const uint8_t *)p)[0] << 8);
}

static inline void
fc_be32enc(void *p, uint32_t u32)
{
	((uint8_t *)p)[3] = u32 & 0xff;
	((uint8_t *)p)[2] = (u32 >> 8) & 0xff;
	((uint8_t *)p)[1] = (u32 >> 16) & 0xff;
	((uint8_t *)p)[0] = (u32 >> 24) & 0xff;
}

static inline uint32_t
fc_be32dec(const void *p)
{
	return ((uint32_t)((const uint8_t *)p)[3] |
	    (uint32_t)((const uint8_t *)p)[2] << 8 |
	    (uint32_t)((const uint8_t *)p)[1] << 16 |
	    (uint32_t)((const uint8_t *)p)[0] << 24);
}

static inline void
fc_be64enc(void *p, uint64_t u64)
{
	((uint8_t *)p)[7] = u64 & 0xff;
	((uint8_t *)p)[6] = (u64 >> 8) & 0xff;
	((uint8_t *)p)[5] = (u64 >> 16) & 0xff;
	((uint8_t *)p)[4] = (u64 >> 24) & 0xff;
	((uint8_t *)p)[3] = (u64 >> 32) & 0xff;
	((uint8_t *)p)[2] = (u64 >> 40) & 0xff;
	((uint8_t *)p)[1] = (u64 >> 48) & 0xff;
	((uint8_t *)p)[0] = (u64 >> 56) & 0xff;
}

static inline uint64_t
fc_be64dec(const void *p)
{
	return ((uint64_t)((const uint8_t *)p)[7] |
	    (uint64_t)((const uint8_t *)p)[6] << 8 |
	    (uint64_t)((const uint8_t *)p)[5] << 16 |
	    (uint64_t)((const uint8_t *)p)[4] << 24 |
	    (uint64_t)((const uint8_t *)p)[3] << 32 |
	    (uint64_t)((const uint8_t *)p)[2] << 40 |
	    (uint64_t)((const uint8_t *)p)[1] << 48 |
	    (uint64_t)((const uint8_t *)p)[0] << 56);
}

static inline void
fc_le16enc(void *p, uint16_t u16)
{
	((uint8_t *)p)[0] = u16 & 0xff;
	((uint8_t *)p)[1] = (u16 >> 8) & 0xff;
}

static inline uint16_t
fc_le16dec(const void *p)
{
	return ((uint16_t)((const uint8_t *)p)[0] |
	    (uint16_t)((const uint8_t *)p)[1] << 8);
}

static inline void
fc_le32enc(void *p, uint32_t u32)
{
	((uint8_t *)p)[0] = u32 & 0xff;
	((uint8_t *)p)[1] = (u32 >> 8) & 0xff;
	((uint8_t *)p)[2] = (u32 >> 16) & 0xff;
	((uint8_t *)p)[3] = (u32 >> 24) & 0xff;
}

static inline uint32_t
fc_le32dec(const void *p)
{
	return ((uint32_t)((const uint8_t *)p)[0] |
	    (uint32_t)((const uint8_t *)p)[1] << 8 |
	    (uint32_t)((const uint8_t *)p)[2] << 16 |
	    (uint32_t)((const uint8_t *)p)[3] << 24);
}

static inline void
fc_le64enc(void *p, uint64_t u64)
{
	((uint8_t *)p)[0] = u64 & 0xff;
	((uint8_t *)p)[1] = (u64 >> 8) & 0xff;
	((uint8_t *)p)[2] = (u64 >> 16) & 0xff;
	((uint8_t *)p)[3] = (u64 >> 24) & 0xff;
	((uint8_t *)p)[4] = (u64 >> 32) & 0xff;
	((uint8_t *)p)[5] = (u64 >> 40) & 0xff;
	((uint8_t *)p)[6] = (u64 >> 48) & 0xff;
	((uint8_t *)p)[7] = (u64 >> 56) & 0xff;
}

static inline uint64_t
fc_le64dec(const void *p)
{
	return ((uint64_t)((const uint8_t *)p)[0] |
	    (uint64_t)((const uint8_t *)p)[1] << 8 |
	    (uint64_t)((const uint8_t *)p)[2] << 16 |
	    (uint64_t)((const uint8_t *)p)[3] << 24 |
	    (uint64_t)((const uint8_t *)p)[4] << 32 |
	    (uint64_t)((const uint8_t *)p)[5] << 40 |
	    (uint64_t)((const uint8_t *)p)[6] << 48 |
	    (uint64_t)((const uint8_t *)p)[7] << 56);
}

#endif
