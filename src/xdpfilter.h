/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __XDPFILTER_H
#define __XDPFILTER_H

/* Event struct used for ringbuffer events. All values are in host byte
 * order. */
struct event {
	unsigned int host;
        unsigned int dest;
        unsigned short int port;
};

/* Redefine all the macros we need because including headers like
 * linux/if_ether.h causes typedef collisions. For now, copying and pasting is
 * the accepted solution, per the author of libbpf:
 * https://www.spinics.net/lists/bpf/msg39443.html */
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

#endif /* __XDPFILTER_H */
