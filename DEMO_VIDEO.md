# eBPF Network Filtering Demo Video

This guide is written for the verified Ubuntu EC2 environment. It demonstrates both eBPF programs and the userspace map configuration.

## Demo environment

The commands below assume:

```sh
EC2_PUBLIC_IP=100.61.150.167
IFACE=ens5
PROJECT=/tmp/accuknox-ebpf
```

Replace `EC2_PUBLIC_IP` if the instance address changes. The EC2 security group must allow inbound TCP `22`, `4040`, and `4041` from your IP address.

The EC2 host used for verification had:

- Ubuntu Linux x86_64
- Linux kernel `7.0.0-1014-aws`
- Go, Clang/LLVM, Make, bpftool, Python 3, and netcat
- cgroup v2 enabled

## Video structure

Record three terminal views if possible:

1. The EC2 terminal running the eBPF loader.
2. A second EC2 terminal showing listeners or kernel attachment state.
3. Your Mac terminal making HTTP or TCP requests to the EC2 public IP.

## 1. Connect to EC2

From the Mac:

```sh
chmod 600 ~/Downloads/accuknox_assgn.pem
ssh -i ~/Downloads/accuknox_assgn.pem ubuntu@100.61.150.167
```

`chmod 600` protects the private key so OpenSSH will use it. `ssh` creates the encrypted shell session to the EC2 host.

On EC2:

```sh
cd /tmp/accuknox-ebpf
ip route get 1.1.1.1
```

The route command identifies the interface carrying normal outbound traffic. In the verified environment, the result contained `dev ens5`, so the XDP program was attached to `ens5`.

## 2. Start test listeners

Open two EC2 terminals. In terminal A:

```sh
cd /tmp/accuknox-ebpf
python3 -m http.server 4040 --bind 0.0.0.0
```

In terminal B:

```sh
cd /tmp/accuknox-ebpf
python3 -m http.server 4041 --bind 0.0.0.0
```

Each Python process listens for TCP connections and returns a directory listing. These listeners provide visible success/failure output for the packet-filtering test.

From the Mac, verify the baseline before attaching eBPF:

```sh
curl --connect-timeout 5 http://100.61.150.167:4040
curl --connect-timeout 5 http://100.61.150.167:4041
```

Both requests should return an HTML directory listing. If either fails before eBPF is attached, check the listener and security-group rule first.

## 3. Problem 1: XDP TCP port drop

In terminal C on EC2:

```sh
cd /tmp/accuknox-ebpf
sudo ./bin/drop -iface ens5 -port 4040
```

Expected output:

```text
dropping TCP destination port 4040 on ens5; Ctrl-C to stop
```

What happens internally:

1. The Go loader opens the compiled eBPF object.
2. It updates the `port_config_map` array map at key `0` with port `4040`.
3. It attaches `drop_tcp_port` at the XDP hook on `ens5`.
4. Incoming packets reach the XDP program before normal network-stack processing.
5. The program parses Ethernet, IPv4, and TCP headers.
6. If the TCP destination port matches the map value, it returns `XDP_DROP`.
7. All other traffic returns `XDP_PASS`.

Verify the attachment from another EC2 terminal:

```sh
sudo bpftool net
```

Expected relevant output:

```text
xdp:
ens5(...) generic id ...
```

From the Mac, test the two ports:

```sh
curl --connect-timeout 5 http://100.61.150.167:4040
```

Expected result: timeout. The SYN packet is dropped at XDP, so the Python server never receives a complete connection.

```sh
curl --connect-timeout 5 http://100.61.150.167:4041
```

Expected result: the Python directory listing. Port `4041` does not match the configured map value and is passed through.

## 4. Demonstrate userspace-configurable port

Stop the loader with `Ctrl-C`. Then change only the userspace argument:

```sh
sudo ./bin/drop -iface ens5 -port 4041
```

The C program did not change. The Go loader writes `4041` into the map instead.

From the Mac:

```sh
curl --connect-timeout 5 http://100.61.150.167:4040
```

Expected: the directory listing.

```sh
curl --connect-timeout 5 http://100.61.150.167:4041
```

Expected: timeout.

Interview explanation:

> The map is the control plane between userspace and the kernel. The loader chooses the policy value, while the eBPF program performs the fast packet decision.

## 5. Problem 2: process-specific TCP allowlist

Stop the Problem 1 loader with `Ctrl-C` before starting this test.

Start local-only listeners in two EC2 terminals:

```sh
python3 -m http.server 4040 --bind 127.0.0.1
```

```sh
python3 -m http.server 4041 --bind 127.0.0.1
```

In another EC2 terminal, attach the process filter:

```sh
cd /tmp/accuknox-ebpf
sudo ./bin/process-filter \
  -cgroup /sys/fs/cgroup \
  -port 4040 \
  -comm nc
```

Expected output:

```text
process "nc" may use TCP destination port 4040 in cgroup /sys/fs/cgroup; Ctrl-C to stop
```

What happens internally:

1. The loader writes port `4040` and process name `nc` into `process_config_map`.
2. It attaches `filter_process_egress` to the cgroup egress hook.
3. For outgoing TCP packets, the program reads the current task name with `bpf_get_current_comm`.
4. If the process name is not `nc`, the packet is passed.
5. If the process is `nc`, only destination port `4040` is passed.
6. Other TCP destination ports return `0`, which drops the packet.

Verify the cgroup attachment:

```sh
sudo bpftool cgroup tree /sys/fs/cgroup
```

Expected relevant output:

```text
cgroup_inet_egress    filter_process_egress
```

Test the allowed port:

```sh
nc -vz -w 3 127.0.0.1 4040
```

Expected: successful connection.

Test the blocked port:

```sh
nc -vz -w 3 127.0.0.1 4041
```

Expected: failure or timeout.

The cgroup filter is intentionally attached only to egress traffic. It is scoped by cgroup first and process `comm` second. For production policy, a cgroup identity is generally stronger than a process name because names can be reused.

## 6. Cleanup

Stop the loaders and Python listeners with `Ctrl-C`.

Confirm that the demo programs were detached:

```sh
sudo bpftool net
sudo bpftool cgroup tree /sys/fs/cgroup
```

The XDP entry for `ens5` and the `filter_process_egress` entry should no longer appear. Existing unrelated system cgroup programs should remain.

## Troubleshooting

### Port 4041 says connection refused

That means no listener is running on port `4041`. Check:

```sh
sudo ss -ltnp | grep -E ':4040|:4041'
```

### Both ports time out

Check that the Python listeners are running and that the security group allows TCP `4040` and `4041` from your current public IP.

### The process filter does not block `nc`

Check the actual Linux process name:

```sh
ps -eo pid,comm,args | grep nc
```

Use the exact `comm` value with the loader's `-comm` option. The value is limited to 15 visible bytes.

### Program attachment fails

Check kernel support and privileges:

```sh
uname -a
sudo bpftool feature probe kernel | head -80
id
```

The loader needs root or equivalent BPF/network administration capabilities.
