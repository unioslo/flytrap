/*-
 * Copyright (c) 2014 Dag-Erling Smørgrav
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

#ifndef FC_ENDIAN_H_INCLUDED
#define FC_ENDIAN_H_INCLUDED

#if HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#if HAVE_ENDIAN_H
#include <endian.h>
#endif

#if !HAVE_DECL_BSWAP16
#define bswap16 fc_bswap16
#endif
#if !HAVE_DECL_BSWAP32
#define bswap32 fc_bswap32
#endif
#if !HAVE_DECL_BSWAP64
#define bswap64 fc_bswap64
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
#if !HAVE_DECL_HTOBE16
#define htobe16 fc_htobe16
#endif
#if !HAVE_DECL_BE16TOH
#define be16toh fc_be16toh
#endif
#if !HAVE_DECL_HTOLE16
#define htole16 fc_htole16
#endif
#if !HAVE_DECL_LE16TOH
#define le16toh fc_le16toh
#endif
#if !HAVE_DECL_HTOBE32
#define htobe32 fc_htobe32
#endif
#if !HAVE_DECL_BE32TOH
#define be32toh fc_be32toh
#endif
#if !HAVE_DECL_HTOLE32
#define htole32 fc_htole32
#endif
#if !HAVE_DECL_LE32TOH
#define le32toh fc_le32toh
#endif
#if !HAVE_DECL_HTOBE64
#define htobe64 fc_htobe64
#endif
#if !HAVE_DECL_BE64TOH
#define be64toh fc_be64toh
#endif
#if !HAVE_DECL_HTOLE64
#define htole64 fc_htole64
#endif
#if !HAVE_DECL_LE64TOH
#define le64toh fc_le64toh
#endif

static inline uint16_t
fc_bswap16(uint16_t u16)
{
#if HAVE___BUILTIN_BSWAP16
	return (__builtin_bswap16(u16));
#else
	return (((u16 & 0x00ffU) >> 0) << 8 |
	    ((u16 & 0xff00U) >> 8) << 0);
#endif
}

static inline uint32_t
fc_bswap32(uint32_t u32)
{
#if HAVE___BUILTIN_BSWAP32
	return (__builtin_bswap32(u32));
#else
	return (((u32 & 0x000000ffLU) >> 0) << 24 |
	    ((u32 & 0x0000ff00LU) >> 8) << 16 |
	    ((u32 & 0x00ff0000LU) >> 16) << 8 |
	    ((u32 & 0xff000000LU) >> 24) << 0);
#endif
}

static inline uint64_t
fc_bswap64(uint64_t u64)
{
#if HAVE___BUILTIN_BSWAP64
	return (__builtin_bswap64(u64));
#else
	return (((u64 & 0x00000000000000ffLLU) >> 0) << 56 |
	    ((u64 & 0x000000000000ff00LLU) >> 8) << 48 |
	    ((u64 & 0x0000000000ff0000LLU) >> 16) << 40 |
	    ((u64 & 0x00000000ff000000LLU) >> 24) << 32 |
	    ((u64 & 0x000000ff00000000LLU) >> 32) << 24 |
	    ((u64 & 0x0000ff0000000000LLU) >> 40) << 16 |
	    ((u64 & 0x00ff000000000000LLU) >> 48) << 8 |
	    ((u64 & 0xff00000000000000LLU) >> 56) << 0);
#endif
}

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

static inline uint16_t
fc_htobe16(uint16_t u16)
{
#if !WORDS_BIGENDIAN
	u16 = fc_bswap16(u16);
#endif
	return (u16);
}

static inline uint16_t
fc_be16toh(uint16_t u16)
{
#if !WORDS_BIGENDIAN
	u16 = fc_bswap16(u16);
#endif
	return (u16);
}

static inline uint16_t
fc_htole16(uint16_t u16)
{
#if WORDS_BIGENDIAN
	u16 = fc_bswap16(u16);
#endif
	return (u16);
}

static inline uint16_t
fc_le16toh(uint16_t u16)
{
#if WORDS_BIGENDIAN
	u16 = fc_bswap16(u16);
#endif
	return (u16);
}

static inline uint32_t
fc_htobe32(uint32_t u32)
{
#if !WORDS_BIGENDIAN
	u32 = fc_bswap32(u32);
#endif
	return (u32);
}

static inline uint32_t
fc_be32toh(uint32_t u32)
{
#if !WORDS_BIGENDIAN
	u32 = fc_bswap32(u32);
#endif
	return (u32);
}

static inline uint32_t
fc_htole32(uint32_t u32)
{
#if WORDS_BIGENDIAN
	u32 = fc_bswap32(u32);
#endif
	return (u32);
}

static inline uint32_t
fc_le32toh(uint32_t u32)
{
#if WORDS_BIGENDIAN
	u32 = fc_bswap32(u32);
#endif
	return (u32);
}

static inline uint64_t
fc_htobe64(uint64_t u64)
{
#if !WORDS_BIGENDIAN
	u64 = fc_bswap64(u64);
#endif
	return (u64);
}

static inline uint64_t
fc_be64toh(uint64_t u64)
{
#if !WORDS_BIGENDIAN
	u64 = fc_bswap64(u64);
#endif
	return (u64);
}

static inline uint64_t
fc_htole64(uint64_t u64)
{
#if WORDS_BIGENDIAN
	u64 = fc_bswap64(u64);
#endif
	return (u64);
}

static inline uint64_t
fc_le64toh(uint64_t u64)
{
#if WORDS_BIGENDIAN
	u64 = fc_bswap64(u64);
#endif
	return (u64);
}

#endif
