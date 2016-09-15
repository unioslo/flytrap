AC_PREREQ([2.59])
AC_INIT([Flycatcher], [0.20160915], [d.e.smorgrav@usit.uio.no],
    [flycatcher], [https://www.github.com/unioslo/flycatcher])
AC_CONFIG_SRCDIR([sbin/flytrap/flycatcher.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AM_CONFIG_HEADER(include/config.h)

############################################################################
#
# Toolchain
#

# C compiler and features
AC_LANG(C)
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CPP
AC_GNU_SOURCE
AC_C_CONST
AC_C_RESTRICT
AC_C_VOLATILE

# other programs
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_PATH_PROGS([Z], [xz bzip2 gzip])
AC_PATH_PROGS([UNZ], [unxz bunzip2 gunzip])

############################################################################
#
# Headers and functions
#

AC_CHECK_HEADERS([endian.h sys/endian.h])
AX_GCC_BUILTIN([__builtin_bswap16])
AX_GCC_BUILTIN([__builtin_bswap32])
AX_GCC_BUILTIN([__builtin_bswap64])
AC_CHECK_DECLS([
    bswap16, bswap32, bswap64,
    be16enc, be16dec, le16enc, le16dec,
    be32enc, be32dec, le32enc, le32dec,
    be64enc, be64dec, le64enc, le64dec,
    htobe16, be16toh, htole16, le16toh,
    htobe32, be32toh, htole32, le32toh,
    htobe64, be64toh, htole64, le64toh,
    nothing
], [], [], [[
#if HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#if HAVE_ENDIAN_H
#include <endian.h>
#endif
]])
AC_CHECK_FUNCS([strlcat strlcmp strlcpy])
AC_CHECK_HEADERS([sys/socket.h netinet/in.h])
AC_CHECK_MEMBERS([struct sockaddr_in.sin_len], [], [], [[
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]])
AC_CHECK_HEADERS([pcap.h pcap/pcap.h])

############################################################################
#
# Extra libraries
#

save_LIBS="${LIBS}"
LIBS=""
AC_SEARCH_LIBS([pcap_open_live], [pcap])
LIBPCAP="${LIBS}"
LIBS="${save_LIBS}"
AC_SUBST(LIBPCAP)

# options
AC_ARG_ENABLE([developer-warnings],
    AS_HELP_STRING([--enable-developer-warnings], [enable strict warnings (default is NO)]),
    [CFLAGS="${CFLAGS} -Wall -Wextra -Wcast-qual -Wshadow"])
AC_ARG_ENABLE([debugging-symbols],
    AS_HELP_STRING([--enable-debugging-symbols], [enable debugging symbols (default is NO)]),
    [CFLAGS="${CFLAGS} -O0 -g -fno-inline"])
AC_ARG_ENABLE([werror],
    AS_HELP_STRING([--enable-werror], [use -Werror (default is NO)]),
    [CFLAGS="${CFLAGS} -Werror"])

# output
AC_CONFIG_FILES([
    Makefile
    include/Makefile
    lib/Makefile
    lib/libft/Makefile
    bin/Makefile
    bin/fly/Makefile
    sbin/Makefile
    sbin/flytrap/Makefile
    rc/Makefile
    rc/flycatcher.logrotate
    rc/flycatcher.systemd
    t/Makefile
])
AC_OUTPUT
