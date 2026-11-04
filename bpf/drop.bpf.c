#include "bpf_helpers.h"
#include "bpf_endian.h"

struct ethhdr { __u8 h_dest[6], h_source[6]; __be16 h_proto; };
struct iphdr { __u8 ihl:4, version:4; __u8 tos; __u16 tot_len, id, frag_off; __u8 ttl, protocol; __u16 check; __u32 saddr, daddr; };
struct tcphdr { __u16 source, dest; __u32 seq, ack_seq; __u8 doff:4, res1:4; __u8 flags; __u16 window, check, urg_ptr; };

struct port_config { __u16 port; };

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct port_config);
} port_config_map SEC(".maps");

SEC("xdp")
int drop_tcp_port(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u32 key = 0;
	struct port_config *cfg;

	if ((void *)(eth + 1) > end || eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > end || ip->protocol != IPPROTO_TCP)
		return XDP_PASS;
	if ((void *)ip + ip->ihl * 4 > end)
		return XDP_PASS;
	struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
	if ((void *)(tcp + 1) > end)
		return XDP_PASS;

	cfg = bpf_map_lookup_elem(&port_config_map, &key);
	if (cfg && tcp->dest == bpf_htons(cfg->port))
		return XDP_DROP;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
