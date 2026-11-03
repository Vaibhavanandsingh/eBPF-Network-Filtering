# AccuKnox eBPF evaluation

This repository contains two Linux eBPF demonstrations and an explanation of the Go question from the assignment.

Important: eBPF programs require Linux. The supplied development machine is macOS, so compilation and live attachment must be performed in a Linux VM, cloud instance, or the provided Docker environment. Run the demo as root (or with the capabilities listed below).

## Layout

- `bpf/drop.bpf.c` — XDP program that drops TCP packets whose destination port is in a userspace-updated map.
- `bpf/process_filter.bpf.c` — cgroup egress program that permits one TCP destination port for one process name and drops that process's other TCP egress traffic.
- `cmd/drop` and `cmd/process-filter` — Go loaders.
- `EXPLANATION.md` — line-by-line Go explanation, design notes, and demo script.

## Build on Linux

Install Go, clang/LLVM with the BPF target, and kernel headers. Then:

```sh
make generate
make
```

`make generate` runs cilium/ebpf's `bpf2go`, which generates the Go bindings from the C programs. The generated files are intentionally build artifacts and are ignored by git.

## Quick usage

```sh
# Find the interface used by the target service.
ip route get 1.1.1.1

# Drop TCP packets arriving at port 4040 on eth0; -port can be changed at runtime.
sudo ./bin/drop -iface eth0 -port 4040

# Allow only TCP destination port 4040 for process name myprocess.
sudo ./bin/process-filter -cgroup /sys/fs/cgroup -port 4040 -comm myprocess
```

Press Ctrl-C to detach. See `EXPLANATION.md` for a repeatable network namespace demo and caveats about process attribution.
