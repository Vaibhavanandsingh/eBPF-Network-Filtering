//go:build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type process_config process_filter ../../bpf/process_filter.bpf.c -- -I../../bpf

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 directory to attach to")
	port := flag.Uint("port", 4040, "only allowed TCP destination port")
	comm := flag.String("comm", "myprocess", "Linux process name (maximum 15 characters)")
	flag.Parse()
	if *port > 65535 || len(*comm) == 0 || len(*comm) >= 16 {
		fatal("port must be 0..65535 and comm must be 1..15 bytes")
	}
	var objs processFilterObjects
	if err := loadProcessFilterObjects(&objs, nil); err != nil {
		fatal(err)
	}
	defer objs.Close()
	var cfg processFilterProcessConfig
	cfg.Port = uint16(*port)
	copy(cfg.Comm[:], *comm)
	if err := objs.ProcessConfig.Put(uint32(0), cfg); err != nil {
		fatal(err)
	}
	f, err := os.Open(*cgroup)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	l, err := link.AttachCgroup(link.CgroupOptions{Path: *cgroup, Attach: ebpf.AttachCGroupInetEgress, Program: objs.FilterProcessEgress})
	if err != nil {
		fatal(err)
	}
	defer l.Close()
	fmt.Printf("process %q may use TCP destination port %d in cgroup %s; Ctrl-C to stop\n", *comm, *port, *cgroup)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func fatal(v interface{}) { fmt.Fprintln(os.Stderr, v); os.Exit(1) }
