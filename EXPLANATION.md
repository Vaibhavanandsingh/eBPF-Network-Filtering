# Explanation and demo guide

## What came from the assignment document

The attached document asks for three things: (1) drop TCP packets on a configurable port, (2) allow one TCP port for a named process and drop that process's other traffic, and (3) explain the supplied Go snippet. It also says the goal is a working demo. The document is the specification; the design choices below are implementation details added to make the demo reproducible.

## Problem 1: configurable XDP drop

`drop.bpf.c` is attached at XDP, the earliest practical receive hook for packets arriving on an interface. It checks Ethernet, IPv4, and TCP headers. A one-entry array map holds the port in host byte order. The Go loader writes the selected value before attachment. The TCP destination port is network byte order in the packet, so the program compares it with `bpf_htons(cfg->port)`. Matching packets return `XDP_DROP`; every other packet returns `XDP_PASS`.

The map is the userspace-to-kernel control plane. Change `-port` and restart the loader, or extend the loader to call `objs.PortConfig.Put` again while it is running; the BPF program reads the new value on its next packet.

## Problem 2: process-specific allowlist

`process_filter.bpf.c` is a `cgroup_skb/egress` program. It reads the current task's `comm` (the Linux process name, up to 15 visible bytes) and the destination TCP port from the socket-buffer context. If the process name matches the configured name, only the configured destination port returns `1` (allow); other TCP destinations return `0` (drop). Non-TCP traffic is passed through so the demo does not accidentally break unrelated traffic; both IPv4 and IPv6 TCP are covered.

The program must be attached to a cgroup containing the target process. This is important: a process name alone is not a globally reliable identity, and inbound packets are often handled by kernel context rather than the receiving userspace task. This implementation deliberately enforces the requirement for the process's outbound TCP traffic, where cgroup egress has the useful current-task context. For production-grade identity, combine cgroups with a policy keyed by cgroup ID, or use an LSM/socket-level design.

## Go snippet, line by line

```go
cnp := make(chan func(), 10)
```

Creates a buffered channel whose element type is `func()`. It can hold ten function values without a receiver immediately being ready. The channel is a small work queue: producers send jobs and workers receive jobs. It is not a channel that runs functions automatically.

```go
for i := 0; i < 4; i++ {
    go func() {
        for f := range cnp {
            f()
        }
    }()
}
```

The loop starts four goroutines. Each worker ranges over the channel, waits for a function, and invokes it. Four is an arbitrary concurrency level chosen by the author; it could represent four independent workers, or be selected from CPU count/workload size. The loop variable is not used, and each iteration launches the same worker function. A worker loop ends only when `cnp` is closed.

```go
cnp <- func() { fmt.Println("HERE1") }
```

Sends one function value to the queue. Because the queue has capacity ten, this send normally completes immediately, even if no worker has received it yet. The function body is not executed by the send; a worker must receive and call it.

```go
fmt.Println("Hello")
```

Prints `Hello` in the main goroutine and then `main` returns. Returning from `main` terminates the entire Go process, including all goroutines. There is no synchronization (`sync.WaitGroup`, a receive, or a sleep), so the workers may never get scheduled before termination. Therefore `HERE1` is not guaranteed and commonly is not printed. If it is printed, that is a scheduling race, not correct synchronization.

The channel is also never closed. Closing it would let workers finish their `range`, but a close alone is not enough here: main still needs to wait for the worker to execute the job. A minimal deterministic pattern is:

```go
var wg sync.WaitGroup
wg.Add(1)
cnp := make(chan func(), 10)
go func() { for f := range cnp { f() } }()
cnp <- func() { defer wg.Done(); fmt.Println("HERE1") }
fmt.Println("Hello")
wg.Wait()
close(cnp)
```

For a reusable worker pool, start N workers, submit jobs, close the channel after all submissions, and wait for a worker `WaitGroup` after the jobs have completed.

## Live demo

### 1. Build and identify an interface

Use a Linux VM or host:

```sh
sudo apt-get install -y clang llvm golang-go make iproute2 netcat-openbsd curl
make
IFACE=$(ip route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
echo "$IFACE"
```

### 2. Problem 1 with a local listener

In terminal A, run a TCP listener and verify it works before loading eBPF:

```sh
nc -l 4040
echo test | nc -v 127.0.0.1 4040
```

For an XDP demonstration use traffic arriving on the selected interface. Put a listener on another host or VM at port 4040, then from the client run:

```sh
sudo ./bin/drop -iface "$IFACE" -port 4040
nc -v <server-ip> 4040       # should time out or fail while the program is attached
nc -v <server-ip> 4041       # should reach a listener on 4041, if one exists
```

Run `sudo tcpdump -ni "$IFACE" tcp` in another terminal. Seeing packets on the wire but no application connection demonstrates that the drop occurs at the receive hook. Ctrl-C detaches the program. XDP generic mode is selected for compatibility; native driver mode can be faster when supported.

### 3. Problem 2 with a process name

The simplest reproducible test uses `nc` as the target process. Start listeners on a server at ports 4040 and 4041. Attach the cgroup program:

```sh
sudo ./bin/process-filter -cgroup /sys/fs/cgroup -port 4040 -comm nc
```

From another terminal:

```sh
nc -v <server-ip> 4040   # allowed
nc -v <server-ip> 4041   # dropped for nc
curl -v http://<server-ip>:4041/  # curl is not named nc, so it is not filtered
```

On systems where attaching to the root cgroup is disallowed, create a delegated cgroup and move the test process into it:

```sh
sudo mkdir /sys/fs/cgroup/ebpf-demo
echo $$ | sudo tee /sys/fs/cgroup/ebpf-demo/cgroup.procs
sudo ./bin/process-filter -cgroup /sys/fs/cgroup/ebpf-demo -port 4040 -comm nc
```

In a real demo, explain that process filtering is scoped by cgroup first and `comm` second. The loader's map write configures the allowlisted port and name; each egress packet then follows the match/allow/drop path without a userspace round trip.

### Troubleshooting

- `operation not permitted`: run as root and check `CAP_BPF`, `CAP_NET_ADMIN`, and cgroup delegation.
- `invalid argument` when loading: check kernel version, clang BPF support, and verifier output with `bpftool prog show` / `bpftool prog dump xlated id <id>`.
- No XDP effect: verify that the selected interface is the actual ingress interface and test traffic from another network namespace or host; loopback and local delivery may not exercise the expected path.
- The process filter does not block a program: verify its Linux `comm` with `ps -o pid,comm,args`, and verify it is in the attached cgroup with `cat /proc/<pid>/cgroup`.
