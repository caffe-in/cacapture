
#include <linux/version.h>
#include <asm/ptrace.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdbool.h>
#include <errno.h>
#include <stddef.h>
#ifndef static_always_inline
#define static_always_inline static inline __attribute__ ((__always_inline__))
#endif

#define MAX_CPU         256
#define NAME(N)  __##N

#define PROGTP(F) SEC("prog/tp/"__stringify(F)) int bpf_prog_tp__##F
#define PROGKP(F) SEC("prog/kp/"__stringify(F)) int bpf_prog_kp__##F
#define KRETPROG(F) SEC("kretprobe/"__stringify(F)) int kretprobe__##F
#define KPROG(F) SEC("kprobe/"__stringify(F)) int kprobe__##F
#define TPPROG(F) SEC("tracepoint/syscalls/"__stringify(F)) int bpf_func_##F
#define TP_SCHED_PROG(F) SEC("tracepoint/sched/"__stringify(F)) int bpf_func_##F
#define __BPF_MAP_DEF(_kt, _vt, _ents) \
	.key_size = sizeof(_kt),       \
	.value_size = sizeof(_vt),     \
	.max_entries = (_ents)


#define MAP_PERARRAY(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_PERCPU_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
}; \
static_always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static_always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static_always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}


#define MAP_HASH(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_HASH, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
}; \
static_always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static_always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static_always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}

#define MAP_ARRAY(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __##name = \
{   \
    .type = BPF_MAP_TYPE_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
}; \
static_always_inline __attribute__((unused)) value_type * name ## __lookup(key_type *key) \
{ \
    return (value_type *) bpf_map_lookup_elem(& __##name, (const void *)key); \
} \
static_always_inline __attribute__((unused)) int name ## __update(key_type *key, value_type *value) \
{ \
    return bpf_map_update_elem(& __##name, (const void *)key, (const void *)value, BPF_ANY); \
} \
static_always_inline __attribute__((unused)) int name ## __delete(key_type *key) \
{ \
    return bpf_map_delete_elem(& __##name, (const void *)key); \
}


#define BPF_HASH3(_name, _key_type, _leaf_type) \
  MAP_HASH(_name, _key_type, _leaf_type, 40960)

#define BPF_HASH4(_name, _key_type, _leaf_type, _size) \
  MAP_HASH(_name, _key_type, _leaf_type, _size)

// helper for default-variable macro function
#define BPF_HASHX(_1, _2, _3, _4, NAME, ...) NAME

#define BPF_HASH(...) \
  BPF_HASHX(__VA_ARGS__, BPF_HASH4, BPF_HASH3)(__VA_ARGS__)


#define MAP_PROG_ARRAY(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __ ## name = \
{   \
    .type = BPF_MAP_TYPE_PROG_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
};

#define MAP_PERF_EVENT(name, key_type, value_type, max_entries) \
struct bpf_map_def SEC("maps") __ ## name = \
{   \
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, \
    __BPF_MAP_DEF(key_type, value_type, max_entries), \
};