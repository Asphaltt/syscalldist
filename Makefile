
.DEFAULT_GOAL = build

CLANG ?= clang
CFLAGS := -O2 -g -Wall $(CFLAGS)

.PHONY: update gogen gotcpdump gotcpdive arplatency ovs-dpdk-profiler syscall-profiler build upload sync

update:
	rm -rf sdn_tcpdump arplatency sdn_tcpdive sdn_tools ovs-dpdk-profiler
	tar -xzf sdn-tools.tgz

gotcpdump: export PATH := $(PATH):$(shell go env GOPATH)/bin
gotcpdump:
	rm -vf sdn_tcpdump/*.o
	cd sdn_tcpdump && go generate
	go build -v -trimpath -o bin/sdn_tcpdump ./sdn_tcpdump

gotcpdive: export PATH := $(PATH):$(shell go env GOPATH)/bin
gotcpdive:
	rm -vf sdn_tcpdive/*.o
	cd sdn_tcpdive && go generate
	go build -v -trimpath -o bin/sdn_tcpdive ./sdn_tcpdive

arplatency: export PATH := $(PATH):$(shell go env GOPATH)/bin
arplatency:
	rm -vf arplatency/*.o
	cd arplatency && go generate
	go build -v -trimpath -o bin/arplatency ./arplatency

ovsdpdk: export PATH := $(PATH):$(shell go env GOPATH)/bin
ovsdpdk:
	rm -vf ovs-dpdk-profiler/*.o
	cd ovs-dpdk-profiler && go generate
	go build -v -trimpath -o bin/ovs-dpdk-profiler ./ovs-dpdk-profiler

syscall: export PATH := $(PATH):$(shell go env GOPATH)/bin
syscall:
	rm -vf syscall-profiler/*.o
	cd syscall-profiler && go generate
	go build -v -trimpath -o bin/syscall-profiler ./syscall-profiler

gomod:
	go mod tidy && go mod vendor

gogen: export PATH := $(PATH):$(shell go env GOPATH)/bin
gogen: export PATH := /lib/llvm-14/bin:$(PATH)
gogen:
	cd sdn_tcpdump && go generate
	cd sdn_tcpdive && go generate
	cd arplatency && go generate
	cd ovs-dpdk-profiler && go generate
	cd syscall-profiler && go generate

build: gogen
	mkdir -p bin
	go build -v -trimpath -o bin/sdn_tcpdump ./sdn_tcpdump
	go build -v -trimpath -o bin/sdn_tcpdive ./sdn_tcpdive
	go build -v -trimpath -o bin/arplatency ./arplatency
	go build -v -trimpath -o bin/ovs-dpdk-profiler ./ovs-dpdk-profiler
	go build -v -trimpath -o bin/syscall-profiler ./syscall-profiler

upload:
	rm -rf sdn-tools.tgz
	tar --exclude-vcs --exclude bin --exclude \*.tgz --exclude \*.log --exclude \*.txt -czf sdn-tools.tgz ./*
	# scp sdn-tools.tgz 10.129.107.229:/home/leonhf/sdn-tools/
	scp sdn-tools.tgz 10.129.107.209:/home/leonhf/sdn-tools/
	# scp sdn-tools.tgz 10.129.109.194:/home/leonhf/sdn-tools/

sync:
	scp root@10.129.107.209:/home/leonhf/sdn-tools/sdn_* .
