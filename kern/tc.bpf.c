// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "vmlinux.h"
#include "maps.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define TC_PACKET_MIN_SIZE 36
#define ARGS_BUF_SIZE 32000
#define SOCKET_ALLOW 1
#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);               \
        _val;                                                           \
    })

struct skb_data_event_t {
    uint64_t ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
//    u8 cmdline[PATH_MAX_LEN];
    u32 len;
    u32 ifindex;
};

struct net_id_t {
    u32 protocol;
    u32 src_port;
    u32 src_ip4;
    u32 dst_port;
    u32 dst_ip4;
//    u32 src_ip6[4];
//    u32 dst_ip6[4];
};

struct net_ctx_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
//    u8 cmdline[PATH_MAX_LEN];
};


////////////////////// ebpf maps //////////////////////
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 10240);
} skb_events SEC(".maps");

struct events {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, u32);
} syscall_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct skb_data_event_t);
    __uint(max_entries, 1);
} skb_data_buffer_heap SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct net_id_t);
    __type(value, struct net_ctx_t);
    __uint(max_entries, 10240);
} network_map SEC(".maps");

////////////////////// General helper functions //////////////////////

static __always_inline void get_proc_cmdline(struct task_struct *task, char *cmdline, int size)
{
    struct mm_struct *mm = READ_KERN(task->mm);
    long unsigned int args_start = READ_KERN(mm->arg_start);
    long unsigned int args_end = READ_KERN(mm->arg_end);
    int len = (args_end - args_start);
    if (len >= size)
        len = size - 1;
    bpf_probe_read(cmdline, len & (size - 1), (const void *)args_start);
}

static __always_inline struct skb_data_event_t *make_skb_data_event() {
    u32 kZero = 0;
    struct skb_data_event_t *event =
        bpf_map_lookup_elem(&skb_data_buffer_heap, &kZero);
    if (event == NULL) {
        return NULL;
    }
    return event;
}

static __always_inline bool skb_revalidate_data(struct __sk_buff *skb,
                                                uint8_t **head, uint8_t **tail,
                                                const u32 offset) {
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }

        *head = (uint8_t *)(long)skb->data;
        *tail = (uint8_t *)(long)skb->data_end;

        if (*head + offset > *tail) {
            return false;
        }
    }

    return true;
}

///////////////////// ebpf functions //////////////////////
static __always_inline int capture_packets(struct __sk_buff *skb, bool is_ingress) {
    // packet data
    unsigned char *data_start = (void *)(long)skb->data;
    unsigned char *data_end = (void *)(long)skb->data_end;
    if (data_start + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK;
    }
    bpf_printk("capture_packets\n", sizeof("capture_packets\n"));
    u32 data_len = (u32)skb->len;
    uint32_t l4_hdr_off;

    // Ethernet headers
    struct ethhdr *eth = (struct ethhdr *)data_start;


    // Simple length check
    if ((data_start + sizeof(struct ethhdr) + sizeof(struct iphdr)) >
        data_end) {
        return TC_ACT_OK;
    }

    // filter out non-IP packets
    // TODO support IPv6
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    l4_hdr_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (!skb_revalidate_data(skb, &data_start, &data_end, l4_hdr_off)) {
        return TC_ACT_OK;
    }

    // IP headers
    struct iphdr *iph = (struct iphdr *)(data_start + sizeof(struct ethhdr));
    // ignore the data which sent to target ip using vxlan
    if (iph->saddr==bpf_htonl(target_ip)||iph->daddr==bpf_htonl(target_ip)){
        bpf_printk("the protocol should be vxlan addr to send %d\n", iph->protocol);
        return TC_ACT_OK;
    }
    struct net_id_t conn_id = {0};
    conn_id.protocol = iph->protocol;
    conn_id.src_ip4 = iph->saddr;
    conn_id.dst_ip4 = iph->daddr;

    struct skb_data_event_t event={0};
    event.ts = bpf_ktime_get_ns();
    event.len = skb->len;
    event.ifindex = skb->ifindex;

    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64)skb->len << 32;

    // via aquasecurity/tracee    tracee.bpf.c tc_probe
    // if net_packet event not chosen, send minimal data only:
    //     timestamp (u64)      8 bytes
    //     pid (u32)            4 bytes
    //     comm (char[])       16 bytes
    //     packet len (u32)     4 bytes
    //     ifindex (u32)        4 bytes
    size_t pkt_size = TC_PACKET_MIN_SIZE;
    bpf_perf_event_output(skb, &skb_events, flags, &event, pkt_size);
    // bpf_printk("the protocol is %d\n", conn_id.protocol);
    return TC_ACT_OK;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier")
int egress_cls_func(struct __sk_buff *skb) {
    return capture_packets(skb, false);
};

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier")
int ingress_cls_func(struct __sk_buff *skb) {
    return capture_packets(skb, true);
    
};