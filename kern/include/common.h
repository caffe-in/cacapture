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

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#ifndef CACAPTURE_COMMON_H
#define CACAPTURE_COMMON_H

#ifdef DEBUG_PRINT
#define debug_bpf_printk(fmt, ...)                     \
    do {                                               \
        char s[] = fmt;                                \
        bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__); \
    } while (0)
#else
#define debug_bpf_printk(fmt, ...)
#endif

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256
#define MAX_DATA_SIZE_OPENSSL 1024 * 4
#define MAX_DATA_SIZE_MYSQL 256
#define MAX_DATA_SIZE_POSTGRES 256
#define MAX_DATA_SIZE_BASH 256

// enum_server_command, via
// https://dev.mysql.com/doc/internals/en/com-query.html COM_QUERT command 03
#define COM_QUERY 3

#define AF_INET 2
#define AF_INET6 10
#define SA_DATA_LEN 14
#define BASH_ERRNO_DEFAULT 128

///////// for TC & XDP ebpf programs in tc.h
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet        */
#define SKB_MAX_DATA_SIZE 2048

// .rodata section bug via : https://github.com/gojue/CACAPTURE/issues/39
#ifndef KERNEL_LESS_5_2
// alawyse, we used it in tc.h
const volatile u64 target_port = 5201;

// Optional Target PID and UID
const volatile u64 target_pid = 0;
const volatile u64 target_uid = 0;
const volatile u64 target_errno = BASH_ERRNO_DEFAULT;
static const volatile uint32_t target_ip = 0xAC100840; // 172.16.8.64 的网络字节序
#else
#endif

char __license[] SEC("license") = "Dual MIT/GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;

#endif
#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif
#define statfunc static __always_inline

#define EBPF_CACHE_SIZE 16

// 数据流方向
enum traffic_direction {
	T_EGRESS,
	T_INGRESS,
};
// 数据协议
enum traffic_protocol {
	PROTO_UNKNOWN = 0,
	PROTO_ORTHER = 1,
	PROTO_HTTP1 = 20,
	PROTO_HTTP2 = 21,
	PROTO_DUBBO = 40,
	PROTO_SOFARPC = 43,
	PROTO_FASTCGI = 44,
	PROTO_BRPC = 45,
	PROTO_MYSQL = 60,
	PROTO_POSTGRESQL = 61,
	PROTO_ORACLE = 62,
	PROTO_REDIS = 80,
	PROTO_MONGO = 81,
	PROTO_KAFKA = 100,
	PROTO_MQTT = 101,
	PROTO_AMQP = 102,
	PROTO_OPENWIRE = 103,
	PROTO_NATS = 104,
	PROTO_PULSAR = 105,
	PROTO_ZMTP = 106,
	PROTO_DNS = 120,
	PROTO_TLS = 121,
	PROTO_CUSTOM = 127,
	PROTO_NUM = 130
};
enum syscall_src_func {
	SYSCALL_FUNC_UNKNOWN,
	SYSCALL_FUNC_WRITE,
	SYSCALL_FUNC_READ,
	SYSCALL_FUNC_SEND,
	SYSCALL_FUNC_RECV,
	SYSCALL_FUNC_SENDTO,
	SYSCALL_FUNC_RECVFROM,
	SYSCALL_FUNC_SENDMSG,
	SYSCALL_FUNC_RECVMSG,
	SYSCALL_FUNC_SENDMMSG,
	SYSCALL_FUNC_RECVMMSG,
	SYSCALL_FUNC_WRITEV,
	SYSCALL_FUNC_READV,
	SYSCALL_FUNC_SENDFILE
};
enum process_data_extra_source {
	DATA_SOURCE_SYSCALL,
	DATA_SOURCE_GO_TLS_UPROBE,
	DATA_SOURCE_GO_HTTP2_UPROBE,
	DATA_SOURCE_OPENSSL_UPROBE,
	DATA_SOURCE_IO_EVENT,
	DATA_SOURCE_GO_HTTP2_DATAFRAME_UPROBE,
	DATA_SOURCE_CLOSE,
};
enum message_type {
	MSG_UNKNOWN,
	// L7协议推断数据类型是请求
	MSG_REQUEST,
	// L7协议推断数据类型是回应
	MSG_RESPONSE,

	// HTTP2 request message end marker
	MSG_REQUEST_END,
	// HTTP2 response message end marker
	MSG_RESPONSE_END,

	// Data reassembly begins
	MSG_REASM_START,
	// Segment of data reassembled
	MSG_REASM_SEG,

	// 无法推断协议类型，先在map中存储等下一次的数据
	// 获取后两者合并，再进行判断。主要场景用于MySQL，Kafka
	// 读数据的行为先读取4字节数据后再读取剩下的数据，要想进行
	// 正确的协议判断需要合并这两部分数据才可以。
	MSG_PRESTORE,
	// 对于l7的协议推断需要再确认逻辑。
	MSG_RECONFIRM,
	// 用于信息相关清理，一般用于socket信息清除
	MSG_CLEAR
};

struct protocol_message_t {
	enum traffic_protocol protocol;
	enum message_type type;
};


