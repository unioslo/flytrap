AM_CPPFLAGS		 = -I$(top_srcdir)/include

sbin_PROGRAMS		 = flytrap

flytrap_SOURCES		 =
flytrap_SOURCES		+= arp.c
flytrap_SOURCES		+= flytrap.c
flytrap_SOURCES		+= log.c
flytrap_SOURCES		+= main.c

# Interface
flytrap_SOURCES		+= iface.c
flytrap_SOURCES		+= packet.c

# Protocol stack
flytrap_SOURCES		+= ether.c
flytrap_SOURCES		+= icmp4.c
flytrap_SOURCES		+= ip4.c
flytrap_SOURCES		+= tcp4.c
flytrap_SOURCES		+= udp4.c

flytrap_LDADD		 = $(LIBPCAP) $(top_builddir)/lib/libft/libft.a

noinst_HEADERS		 =
noinst_HEADERS		+= ethernet.h
noinst_HEADERS		+= flytrap.h
noinst_HEADERS		+= iface.h
noinst_HEADERS		+= packet.h

dist_man8_MANS		 = flytrap.8
