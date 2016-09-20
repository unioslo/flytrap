AM_CPPFLAGS = -I$(top_srcdir)/include

if WITH_TESTS

LIBFT = $(top_builddir)/lib/libft/libft.a

check_PROGRAMS =
check_PROGRAMS += t_ip4a t_ip4p
t_ip4a_LDADD = $(LIBFT) $(LIBCRYB_TEST)
t_ip4p_LDADD = $(LIBFT) $(LIBCRYB_TEST)

TESTS = $(check_PROGRAMS)

endif
