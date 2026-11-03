#ifndef __BPF_ENDIAN_H
#define __BPF_ENDIAN_H
#define __bpf_constant_htons(x) ((__u16)((((x) & 0xff) << 8) | (((x) >> 8) & 0xff)))
#define bpf_htons(x) __bpf_constant_htons(x)
#endif
