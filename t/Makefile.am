AM_CPPFLAGS = -I$(top_srcdir)/include
LIBFT = $(top_builddir)/lib/libft/libft.a
noinst_HEADERS = t_ip4.h

if WITH_TESTS

check_PROGRAMS		 =

check_PROGRAMS		+= t_ip4_addr
t_ip4_addr_LDADD	 = $(LIBFT) $(LIBCRYB_TEST)

check_PROGRAMS		+= t_ip4_range
t_ip4_range_LDADD	 = $(LIBFT) $(LIBCRYB_TEST)

check_PROGRAMS		+= t_ip4_set
t_ip4_set_LDADD		 = $(LIBFT) $(LIBCRYB_TEST)

TESTS = $(check_PROGRAMS)

endif
