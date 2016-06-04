AM_CPPFLAGS		 = -I$(top_srcdir)/include

sbin_PROGRAMS		 = flycatcher

flycatcher_SOURCES	 =
flycatcher_SOURCES	+= arp.c
flycatcher_SOURCES	+= crc32.c
flycatcher_SOURCES	+= flycatcher.c
flycatcher_SOURCES	+= log.c
flycatcher_SOURCES	+= main.c

# Interface
flycatcher_SOURCES	+= iface.c
flycatcher_SOURCES	+= packet.c

# Protocol stack
flycatcher_SOURCES	+= ether.c
flycatcher_SOURCES	+= icmp4.c
flycatcher_SOURCES	+= ip4.c
flycatcher_SOURCES	+= tcp4.c
flycatcher_SOURCES	+= udp4.c

flycatcher_LDADD	 = $(LIBPCAP) $(top_builddir)/lib/libfc/libfc.a

noinst_HEADERS		 =
noinst_HEADERS		+= ethernet.h
noinst_HEADERS		+= flycatcher.h
noinst_HEADERS		+= iface.h
noinst_HEADERS		+= packet.h

dist_man8_MANS		 = flycatcher.8
