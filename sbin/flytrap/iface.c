/*-
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/time.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#elif HAVE_PCAP_H
#include <pcap.h>
#else
#error pcap library required
#endif

#include <ft/ethernet.h>
#include <ft/ip4.h>
#include <ft/log.h>
#include <ft/string.h>
#include <ft/strlcpy.h>

#include "flytrap.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

ether_addr	 flytrap_ether_addr = { FLYTRAP_ETHER_ADDR };

/*
 * Prepare to use the named interface, but do not start capturing yet.
 * Annoyingly, there is no way to tell at this point whether the interface
 * exists and whether we are permitted to use it.
 *
 * TODO: pcap_findalldevs()
 */
iface *
iface_open(const char *name)
{
	char pceb[PCAP_ERRBUF_SIZE];
	iface *i;

	*pceb = '\0';
	if ((i = calloc(1, sizeof *i)) == NULL)
		return (NULL);
	if (strlcpy(i->name, name, sizeof i->name) >= sizeof i->name)
		goto fail;
	memcpy(&i->ether, &flytrap_ether_addr, sizeof(ether_addr));
#if HAVE_PCAP_PCAP_H
	if ((i->pch = pcap_create(i->name, pceb)) == NULL ||
	    pcap_set_promisc(i->pch, 1) != 0 ||
	    pcap_set_snaplen(i->pch, 2048) != 0 ||
	    pcap_set_timeout(i->pch, 100) != 0)
		goto fail;
#else
	if ((i->pch = pcap_open_live(i->name, 2048, 1, 100, pceb)) == NULL)
		goto fail;
#endif
	ft_verbose("%s: interface opened", i->name);
	return (i);
fail:
	if (*pceb)
		ft_error("failed to open %s: %s", i->name, pceb);
	if (i->pch != NULL)
		pcap_close(i->pch);
	free(i);
	return (NULL);
}

int
iface_activate(iface *i)
{
	struct bpf_program fprog;
	string *fstr;
	const char *fsz;

	/* activate interface */
#if HAVE_PCAP_PCAP_H
	if (pcap_activate(i->pch) != 0) {
		ft_error("%s: failed to activate: %s",
		    i->name, pcap_geterr(i->pch));
		return (-1);
	}
#endif
	if (pcap_setdirection(i->pch, PCAP_D_INOUT) != 0) {
		ft_error("%s: failed to set direction: %s",
		    i->name, pcap_geterr(i->pch));
		return (-1);
	}
	ft_verbose("%s: interface activated", i->name);

	/* we only understand Ethernet */
	if (pcap_datalink(i->pch) != DLT_EN10MB) {
		ft_error("%s: not an Ethernet interface", i->name);
		return (-1);
	}

	/* compose and compile filter program */
	fstr = string_new();
	string_printf(fstr,
	    "arp"
	    " or ether dst %02x:%02x:%02x:%02x:%02x:%02x"
	    " or ether dst ff:ff:ff:ff:ff:ff",
	    i->ether.o[0], i->ether.o[1], i->ether.o[2],
	    i->ether.o[3], i->ether.o[4], i->ether.o[5]);
	fsz = string_buf(fstr);
	if (pcap_compile(i->pch, &fprog, fsz, 1, 0xffffffffU) != 0) {
		ft_error("%s: failed to compile filter: %s",
		    i->name, pcap_geterr(i->pch));
		return (-1);
	}
	string_delete(fstr);

	/* install filter program */
	if (pcap_setfilter(i->pch, &fprog) != 0) {
		ft_error("%s: failed to install filter: %s",
		    i->name, pcap_geterr(i->pch));
		pcap_freecode(&fprog);
		return (-1);
	}
	pcap_freecode(&fprog);
	ft_verbose("%s: filter installed: \"%s\"", i->name, fsz);

	/* done */
	return (0);
}

void
iface_close(iface *i)
{

	pcap_close(i->pch);
	free(i);
}

packet *
iface_next(iface *i)
{
	struct pcap_pkthdr *ph;
	const uint8_t *pd;
	packet *p;
	int pcr;

	if ((pcr = pcap_next_ex(i->pch, &ph, &pd)) < 0) {
		ft_error("%s: failed to read packet: %s",
		    i->name, pcap_geterr(i->pch));
		errno = EIO; /* XXX */
		return (NULL);
	} else if (pcr == 0) {
		errno = EAGAIN;
		return (NULL);
	} else if (ph->len > ph->caplen) {
		errno = ENOSPC;
		return (NULL);
	}
	if ((p = calloc(1, sizeof *p)) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	p->i = i;
	p->ts = ph->ts;
	p->data = pd;
	p->len = ph->caplen;
	return (p);
}

int
iface_transmit(packet *p)
{

	if (!ft_dryrun && pcap_inject(p->i->pch, p->data, p->len) != (int)p->len)
		return (-1);
	return (0);
}
