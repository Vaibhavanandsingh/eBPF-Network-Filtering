//go:build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type port_config drop ../../bpf/drop.bpf.c -- -I../../bpf

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

func main() {
	iface := flag.String("iface", "", "interface to attach XDP to (required)")
	port := flag.Uint("port", 4040, "TCP destination port to drop")
	flag.Parse()
	if *iface == "" || *port > 65535 {
		flag.Usage()
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "must run as root or with CAP_BPF/CAP_NET_ADMIN")
		os.Exit(1)
	}

	var objs dropObjects
	if err := loadDropObjects(&objs, nil); err != nil {
		fatal(err)
	}
	defer objs.Close()
	key := uint32(0)
	if err := objs.PortConfig.Put(key, dropPortConfig{Port: uint16(*port)}); err != nil {
		fatal(err)
	}
	idx, err := interfaceIndex(*iface)
	if err != nil {
		fatal(err)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: objs.DropTcpPort, Interface: idx, Flags: link.XDPGenericMode})
	if err != nil {
		fatal(err)
	}
	defer l.Close()
	fmt.Printf("dropping TCP destination port %d on %s; Ctrl-C to stop\n", *port, *iface)

	updated := make(chan os.Signal, 1)
	signal.Notify(updated, os.Interrupt, syscall.SIGTERM)
	<-updated
}

func interfaceIndex(name string) (int, error) {
	i, err := netInterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return i, nil
}

func netInterfaceByName(name string) (int, error) {
	// Kept separate to make the loader's attachment path easy to explain.
	dev, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return dev.Index, nil
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
