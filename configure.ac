AC_PREREQ([2.64])
AC_INIT([Flycatcher], [0.20160419], [d.e.smorgrav@usit.uio.no],
    [flycatcher], [https://www.github.com/unioslo/flycatcher])
AC_CONFIG_SRCDIR([sbin/flycatcher/flycatcher.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign])
AM_CONFIG_HEADER(include/config.h)

# compilers
AC_LANG(C)
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CPP
AC_PROG_RANLIB
AC_GNU_SOURCE
AC_C_CONST
AC_C_RESTRICT
AC_C_VOLATILE

# tools
AC_PROG_INSTALL

# libraries
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
    lib/libfc/Makefile
    sbin/Makefile
    sbin/flycatcher/Makefile
    t/Makefile
])
AC_OUTPUT
