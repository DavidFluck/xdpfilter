/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdpfilter.h"

struct trace_event_raw_bpf_trace_printk___x {};

#undef bpf_printk
#define bpf_printk(fmt, ...)                                                    \
({                                                                              \
     static char ____fmt[] = fmt "\0";                                       \
     if (bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk___x)) {\
             bpf_trace_printk(____fmt, sizeof(____fmt) - 1, ##__VA_ARGS__);  \
        } else {                                                                \
             ____fmt[sizeof(____fmt) - 2] = '\n';                            \
             bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);      \
        }                                                                       \
 })

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* IP blacklist. IPs are in host byte order. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, bool);
} blacklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("xdp_syn")
int xdp_prog_simple(struct xdp_md *ctx)
{
        void *data;
        void *data_end;
        struct ethhdr *ethh;
        u64 offset;
        u16 eth_type;
        struct iphdr *iph;
        enum xdp_action action;
        u8 iphdr_len;
        struct tcphdr *tcph;
        struct event *e;        

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        ethh = data;

        offset = sizeof(*ethh);

        /* Spooky packet. Drop. */
        if (data + offset > data_end) {
                return XDP_DROP;
        }

        eth_type = ethh->h_proto;

        /* Don't care about IPv6 for now. This would be exploitable. */
        if (eth_type == bpf_ntohs(ETH_P_IPV6)) {
                return XDP_PASS;
        }

        /* For now (or longer), we ignore VLAN and VLAN-within-VLAN packets 
         * (802.11q and 802.11ad, respectively). Were this more production-
         * ready, we would need to adjust our IP packet offset accordingly. */

        /* Take apart the IP packet. */
        iph = data + offset;

        if (iph + 1 > data_end) {
                return XDP_DROP;
        }

        /* Check if this is a blocked host, but don't return yet because we
         * still want to count connection attempts, even if they're blocked. */
        u32 host = bpf_ntohl(iph->saddr);
        
        bool found = bpf_map_lookup_elem(&blacklist, (void *)&host);
	if (found) {
		action = XDP_DROP;
                // bpf_printk("Would block: %d\n", iph->saddr);
        } else {
                // bpf_printk("Would allow: %d\n", iph->saddr);
                action = XDP_PASS;
        }

        /* IP packets can have variable-length headers. */
        iphdr_len = iph->ihl * 4;

        /* Spooky packet. Drop. */
        if (offset + iphdr_len > data_end) {
		return XDP_DROP;
        }

        offset += iphdr_len;

        /* Take apart the TCP packet. */
        tcph = data + offset;

        /* Spooky packet. Drop. */
        if (tcph + 1 > data_end) {
                return XDP_DROP;
        }

        /* Check for SYN requests, making sure to ignore SYN ACK. */
        if (tcph->syn && !tcph->ack) {
                e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
                if (!e) {
                        return XDP_PASS;
                }

                /* Fill out the event struct and submit it to userspace. */
                e->host = bpf_ntohl(iph->saddr);
                e->dest = bpf_ntohl(iph->daddr);
                e->port = bpf_ntohs(tcph->dest);

                bpf_ringbuf_submit(e, 0);

                return XDP_PASS;
        }

        return XDP_PASS;
}
