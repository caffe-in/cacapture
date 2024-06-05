#include <vmlinux.h>
#include "type.h"
#include <bpf/bpf_helpers.h>
#include "include/bpf_base.h"
#include "include/socket_trace.h"
#include "include/socket_trace_common.h"

struct sys_enter_init_tail {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_enter_init_tail SEC(".maps");

struct sys_enter_tails {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_enter_tails SEC(".maps");

struct scratch_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, scratch_t);
} scratch_map SEC(".maps");
struct task_info_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, task_info_t);
} task_info_map SEC(".maps");

struct config_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, config_entry_t);
} config_map SEC(".maps");

struct kconfig_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} kconfig_map SEC(".maps");

struct sys_enter_submit_tail {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_enter_submit_tail SEC(".maps");

struct sys_enter_tails {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);
    __type(value, u32);
} sys_enter_tails SEC(".maps");

BPF_HASH(active_write_args_map, __u64, struct data_args_t)

BPF_HASH(socket_info_map, __u64, struct socket_info_s)

MAP_PERARRAY(members_offset, __u32, struct member_fields_offset, 1)

MAP_PERARRAY(ctx_info, __u32, struct ctx_info_s, 1)

MAP_ARRAY(kprobe_port_bitmap, __u32, struct kprobe_port_bitmap, 2)