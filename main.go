package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sort"
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

//go:generate go run ./gogen syscallname.go

func main() {
	var filterPid, filterSyscallID uint32
	var filterSyscallName, kernelBtf string
	var listSyscall bool
	flag.Uint32Var(&filterPid, "pid", 0, "filter pid")
	flag.Uint32Var(&filterSyscallID, "syscall", 0, "filter syscall id")
	flag.StringVar(&filterSyscallName, "syscall-name", "", "filter syscall name")
	flag.StringVar(&kernelBtf, "kernel-btf", "", "kernel BTF file")
	flag.BoolVarP(&listSyscall, "list-syscall", "l", false, "list syscalls of amd64 Linux used by Go syscall")
	flag.Parse()

	if listSyscall {
		printSyscall()
		return
	}

	if filterSyscallID == 0 && filterSyscallName != "" {
		filterSyscallID = uint32(syscallsName2num[filterSyscallName])
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

	printHist(objs.Hists)
}

const (
	maxSlots = 36
)

type slot struct {
	Slots [maxSlots]uint64
}

func printHist(m *ebpf.Map) {
	slotNumber := 512
	slots := make([]slot, runtime.NumCPU())

	for key := uint32(0); key < uint32(slotNumber); key++ {
		err := m.Lookup(key, &slots)
		if err != nil {
			log.Printf("Failed to lookup key(%d): %v", key, err)
			return
		}

		var s slot
		for i, slot := range slots {
			s.Slots[i] += slot.Slots[i]
		}

		sum := lodash.Sum(s.Slots[:])

		if sum == 0 {
			continue
		}

		name := syscallsNum2name[int(key)]
		if name != "" {
			name = "/" + name
		}

		fmt.Println()
		fmt.Printf("Histogram for syscall(%d%s) (sum %d):\n", key, name, sum)
		histogram.PrintLog2Hist(s.Slots[:], "usecs")
	}
}

func printSyscall() {
	type syscall struct {
		no   int
		name string
	}
	var syscalls []syscall

	for no, name := range syscallsNum2name {
		syscalls = append(syscalls, syscall{no, name})
	}

	sort.Slice(syscalls, func(i, j int) bool {
		return syscalls[i].no < syscalls[j].no
	})

	for _, s := range syscalls {
		fmt.Printf("%s -> %d\n", s.name, s.no)
	}
}
