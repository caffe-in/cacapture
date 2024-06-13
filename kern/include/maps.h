#ifndef DF_MAPS_H
#define DF_MAPS_H

#include "vmlinux.h"
#include "type.h"
#include <bpf/bpf_helpers.h>
#include "bpf_base.h"
#include "socket_trace.h"
#include "socket_trace_common.h"

#define PROTO_INFER_CACHE_SIZE  80

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

// struct config_map {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, u32);
//     __type(value, config_entry_t);
// } config_map SEC(".maps");

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

BPF_HASH(active_write_args_map, __u64, struct data_args_t)

BPF_HASH(socket_info_map, __u64, struct socket_info_s)

MAP_PERARRAY(members_offset, __u32, struct member_fields_offset, 1)

MAP_PERARRAY(ctx_info, __u32, struct ctx_info_s, 1)

MAP_ARRAY(kprobe_port_bitmap, __u32, struct kprobe_port_bitmap, 2)

MAP_PERARRAY(trace_conf_map, __u32, struct trace_conf_t, 1)

MAP_ARRAY(protocol_filter, int, int, PROTO_NUM)

MAP_ARRAY(proto_ports_bitmap, __u32, ports_bitmap_t, PROTO_NUM)

MAP_ARRAY(proto_infer_cache_map, __u32, struct proto_infer_cache_t, PROTO_INFER_CACHE_SIZE)

MAP_PROG_ARRAY(progs_jmp_kp_map, __u32, __u32, PROG_KP_NUM)
MAP_PROG_ARRAY(progs_jmp_tp_map, __u32, __u32, PROG_TP_NUM)

MAP_PERARRAY(data_buf, __u32, struct __socket_data_buffer, 1)

MAP_PERF_EVENT(socket_data, int, __u32, MAX_CPU)

BPF_HASH(trace_map, struct trace_key_t, struct trace_info_t)

BPF_HASH(active_read_args_map, __u64, struct data_args_t)

MAP_ARRAY(trace_stats_map, __u32, struct trace_stats, 1)

MAP_ARRAY(allow_reasm_protos_map, int, bool, PROTO_NUM)

BPF_HASH(socket_role_map, __u64, __u32);

MAP_PERARRAY(io_event_buffer, __u32, struct __io_event_buffer, 1)

#endif