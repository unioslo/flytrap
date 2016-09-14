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

#include <fc/log.h>
#include <fc/sbuf.h>
#include <fc/strutil.h>

#include "flycatcher.h"
#include "ethernet.h"
#include "iface.h"
#include "packet.h"

ether_addr	 flycatcher_ether_addr = { FLYCATCHER_ETHER_ADDR };

/*
 * Prepare to use the named interface, but do not start capturing yet.
 * Annoyingly, there is no way to tell at this point whether the interface
 * exists and whether we are permitted to use it.
 *
 * TODO: pcap_findalldevs()
 */
struct iface *
iface_open(const char *name)
{
	char pceb[PCAP_ERRBUF_SIZE];
	struct iface *i;

	*pceb = '\0';
	if ((i = calloc(1, sizeof *i)) == NULL)
		return (NULL);
	if (strlcpy(i->name, name, sizeof i->name) >= sizeof i->name)
		goto fail;
	memcpy(&i->ether, &flycatcher_ether_addr, sizeof(ether_addr));
	if ((i->pch = pcap_create(i->name, pceb)) == NULL ||
	    pcap_set_promisc(i->pch, 1) != 0 ||
	    pcap_set_snaplen(i->pch, 2048) != 0 ||
	    pcap_set_timeout(i->pch, 100) != 0)
		goto fail;
	fc_verbose("%s: interface opened", i->name);
	return (i);
fail:
	if (*pceb)
		fc_error("failed to open %s: %s", i->name, pceb);
	if (i->pch != NULL)
		pcap_close(i->pch);
	free(i);
	return (NULL);
}

int
iface_activate(struct iface *i)
{
	char fsz[1024];
	struct sbuf fsb;
	struct bpf_program fprog;

	/* activate interface */
	if (pcap_activate(i->pch) != 0 ||
	    pcap_setdirection(i->pch, PCAP_D_INOUT) != 0) {
		fc_error("%s: failed to activate: %s",
		    i->name, pcap_geterr(i->pch));
		return (-1);
	}
	fc_verbose("%s: interface activated", i->name);

	/* we only understand Ethernet */
	if (pcap_datalink(i->pch) != DLT_EN10MB) {
		fc_error("%s: not an Ethernet interface", i->name);
		return (-1);
	}

	/* compose and compile filter program */
	sbuf_new(&fsb, fsz, sizeof fsz, 0);
	sbuf_printf(&fsb,
	    "arp"
	    " or ether dst %02x:%02x:%02x:%02x:%02x:%02x"
	    " or ether dst ff:ff:ff:ff:ff:ff",
	    i->ether.o[0], i->ether.o[1], i->ether.o[2],
	    i->ether.o[3], i->ether.o[4], i->ether.o[5]);
	sbuf_finish(&fsb);
	if (pcap_compile(i->pch, &fprog, fsz, 1, 0xffffffffU) != 0) {
		fc_error("%s: failed to compile filter: %s",
		    i->name, pcap_geterr(i->pch));
		return (-1);
	}

	/* install filter program */
	if (pcap_setfilter(i->pch, &fprog) != 0) {
		fc_error("%s: failed to install filter: %s",
		    i->name, pcap_geterr(i->pch));
		pcap_freecode(&fprog);
		return (-1);
	}
	pcap_freecode(&fprog);
	fc_verbose("%s: filter installed: \"%s\"", i->name, fsz);

	/* done */
	return (0);
}

void
iface_close(struct iface *i)
{

	pcap_close(i->pch);
	free(i);
}

struct packet *
iface_next(struct iface *i)
{
	struct pcap_pkthdr *ph;
	const uint8_t *pd;
	struct packet *p;
	int pcr;

	if ((pcr = pcap_next_ex(i->pch, &ph, &pd)) < 0) {
		fc_error("%s: failed to read packet: %s",
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
iface_transmit(struct iface *i, struct packet *p)
{

	if (!fc_dryrun && pcap_inject(i->pch, p->data, p->len) != (int)p->len)
		return (-1);
	return (0);
}
