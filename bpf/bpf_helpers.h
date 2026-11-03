#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct __sk_buff {
	__u32 len, pkt_type, mark, queue_mapping, protocol, vlan_present, vlan_tci, vlan_proto;
	__u32 priority, ingress_ifindex, ifindex, tc_index, cb[5], hash, tc_classid, data, data_end;
	__u32 napi_id, family, remote_ip4, local_ip4, remote_ip6[4], local_ip6[4];
	__u32 remote_port, local_port, data_meta, flow_keys;
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0
#define __always_inline inline __attribute__((always_inline))
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define XDP_PASS 2
#define XDP_DROP 1

struct bpf_map_def_legacy { __u32 type, key_size, value_size, max_entries; };
#endif
