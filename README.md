# syscalldist

**syscalldist** is the tool to profile syscalls.

## Build and run

```bash
# git clone https://github.com/Asphaltt/syscalldist.git
# cd syscalldist
# go generate && go build
# ./syscalldist -h
Usage of ./syscalldist:
      --kernel-btf string     kernel BTF file
  -l, --list-syscall          list syscalls of amd64 Linux used by Go syscall
      --pid uint32            filter pid
      --syscall uint32        filter syscall id
      --syscall-name string   filter syscall name
pflag: help requested
#  ./syscalldist
2023/03/01 14:12:19 Attached raw_tracepoint(sys_enter)
2023/03/01 14:12:19 Attached raw_tracepoint(sys_exit)
2023/03/01 14:12:19 Hit Ctrl-C to end.
^C
Histogram for syscall(0/read) (sum 1):
     usecs               : count         distribution
         0 -> 1          : 0             |                                        |
         2 -> 3          : 0             |                                        |
         4 -> 7          : 0             |                                        |
         8 -> 15         : 1             |****************************************|

Histogram for syscall(1/write) (sum 2):
     usecs               : count         distribution
         0 -> 1          : 0             |                                        |
         2 -> 3          : 0             |                                        |
         4 -> 7          : 2             |****************************************|

Histogram for syscall(9/mmap) (sum 1):
     usecs               : count         distribution
         0 -> 1          : 0             |                                        |
         2 -> 3          : 0             |                                        |
         4 -> 7          : 1             |****************************************|
```

## Raw tracepoints

`syscalldist` runs on raw tracepoints `sys_enter` and `sys_exit`.

## License

Apache-2.0 license
