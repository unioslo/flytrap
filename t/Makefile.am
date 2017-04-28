AM_CPPFLAGS = -I$(top_srcdir)/include $(CRYB_TEST_CFLAGS)
LIBFT = $(top_builddir)/lib/libft/libft.a
noinst_HEADERS = t_ip4.h

if HAVE_CRYB_TEST

check_PROGRAMS		 =

check_PROGRAMS		+= t_ip4_addr
t_ip4_addr_LDADD	 = $(LIBFT) $(CRYB_TEST_LIBS)

check_PROGRAMS		+= t_ip4_range
t_ip4_range_LDADD	 = $(LIBFT) $(CRYB_TEST_LIBS)

check_PROGRAMS		+= t_ip4_set
t_ip4_set_LDADD		 = $(LIBFT) $(CRYB_TEST_LIBS)

check_PROGRAMS		+= t_string
t_string_LDADD		 = $(LIBFT) $(CRYB_TEST_LIBS)

check_PROGRAMS		+= t_strlcat
t_strlcat_LDADD		 = $(LIBFT) $(CRYB_TEST_LIBS)

check_PROGRAMS		+= t_strlcpy
t_strlcpy_LDADD		 = $(LIBFT) $(CRYB_TEST_LIBS)

TESTS = $(check_PROGRAMS)

endif
