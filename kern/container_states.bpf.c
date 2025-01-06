// include all bpf.c files
#define __TARGET_ARCH_x86_64

#include "syscall.bpf.c"
#include "files.bpf.c"
#include "mountsnoop.bpf.c"

char _license[] SEC("license") = "GPL";
