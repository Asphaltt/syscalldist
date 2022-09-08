package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"syscalldist/pkg/histogram"
	"syscalldist/pkg/lodash"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang syscall ./ebpf/syscall.c -- -I./ebpf/headers -Wall -D__TARGET_ARCH_x86

func main() {
	var filterPid, filterSyscallID uint32
	var kernelBtf string
	flag.Uint32Var(&filterPid, "pid", 0, "filter pid")
	flag.Uint32Var(&filterSyscallID, "syscall", 0, "filter syscall id")
	flag.StringVar(&kernelBtf, "kernel-btf", "", "kernel BTF file")
	flag.Parse()

	if filterPid == 0 {
		log.Fatalf("--pid is required")
	}
	if filterSyscallID == 0 {
		log.Fatalf("--syscall is required")
	}

	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	var btfSpec *btf.Spec
	if kernelBtf != "" {
		btfSpec, err = btf.LoadSpec(kernelBtf)
	} else {
		btfSpec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		log.Fatalf("Failed to load btf spec: %v", err)
	}

	bpfSpec, err := loadSyscall()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	rc := map[string]interface{}{
		"filter_pid":        filterPid,
		"filter_syscall_id": filterSyscallID,
	}
	if err := bpfSpec.RewriteConstants(rc); err != nil {
		log.Fatalf("Failed to rewrite const: %v", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec

	var objs syscallObjects
	if err := bpfSpec.LoadAndAssign(&objs, &opts); err != nil {
		log.Fatalf("Failed to load bpf obj: %v", err)
	}

	type rawtp struct {
		name string
		prog *ebpf.Program
	}
	tps := []rawtp{
		{"sys_enter", objs.SysEnter},
		{"sys_exit", objs.SysExit},
	}

	for _, tp := range tps {
		if t, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    tp.name,
			Program: tp.prog,
		}); err != nil {
			log.Printf("Failed to attach raw_tracepoint(%s): %v", tp.name, err)
			return
		} else {
			log.Printf("Attached raw_tracepoint(%s)", tp.name)
			defer t.Close()
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Print("Hit Ctrl-C to end.\n")

	<-ctx.Done()

	printHist(objs.Hists, filterSyscallID)
}

const (
	maxSlots = 36
)

type slot struct {
	Slots [maxSlots]uint64
}

func printHist(m *ebpf.Map, syscallID uint32) {
	slotNumber := 1
	slots := make([]slot, slotNumber)

	for key := uint32(0); key < uint32(slotNumber); key++ {
		err := m.Lookup(key, &slots[key])
		if err != nil {
			log.Printf("Failed to lookup key(%d): %v", key, err)
			return
		}
	}

	for _, s := range slots[:] {
		sum := lodash.Sum(s.Slots[:])

		fmt.Println()
		fmt.Printf("Histogram for syscall(%d) (sum %d):\n", syscallID, sum)
		histogram.PrintLog2Hist(s.Slots[:], "usecs")
	}
}
