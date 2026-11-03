#include "bpf_helpers.h"
#include "bpf_endian.h"

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

struct process_config { __u16 port; char comm[TASK_COMM_LEN]; };

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_config);
} process_config SEC(".maps");

SEC("cgroup_skb/egress")
int filter_process_egress(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct process_config *cfg = bpf_map_lookup_elem(&process_config, &key);
	char comm[TASK_COMM_LEN] = {};
	int i;

	if (!cfg || skb->protocol != bpf_htons(ETH_P_IP) ||
		(skb->family != AF_INET && skb->family != AF_INET6))
		return 1;
	if (bpf_get_current_comm(&comm, sizeof(comm)) < 0)
		return 1;
	#pragma unroll
	for (i = 0; i < TASK_COMM_LEN; i++) {
		if (comm[i] != cfg->comm[i])
			return 1;
		if (comm[i] == '\0')
			return skb->remote_port == cfg->port;
	}
	return skb->remote_port == cfg->port;
}

char LICENSE[] SEC("license") = "GPL";
