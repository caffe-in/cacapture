
#ifndef DF_BPF_SOCKET_TRACE_COMMON_H
#define DF_BPF_SOCKET_TRACE_COMMON_H
#include "vmlinux.h"
#include "common.h"

#define BURST_DATA_BUF_SIZE  16384	// For brust send buffer
struct socket_info_s {
	__u16 l7_proto;

	/*
	 * Indicate whether this socket is allowed for reassembly,
	 * determined by the configuration of protocol reassembly.
	 */
	__u16 allow_reassembly: 1;
	__u16 finish_reasm: 1; // Whether the reassembly is complete.s
	__u16 unused_bits: 15; 
 	__u32 reasm_bytes; // The amount of data bytes that have been reassembled.

	/*
	 * The serial number of the socket read and write data, used to
	 * correct out-of-sequence.
	 *
	 * Sequence number for reading and writing data in the socket, used
	 * to correct data disorder.
	 */
	volatile __u64 seq;

	/*
	 * When reading data of types like MySQL or Kafka, the first step
	 * involves reading 4 bytes followed by reading the remaining data.
	 * Here, the pre-read data is stored for subsequent protocol analysis.
	 */
	__u8 prev_data[EBPF_CACHE_SIZE];
	__u8 direction: 1;
	__u8 pre_direction: 1;
	__u8 unused: 2;
	__u8 role: 3;           // Socket role identifier: ROLE_CLIENT, ROLE_SERVER, ROLE_UNKNOWN
	__u8 tls_end: 1;	// Use the Identity TLS protocol to infer whether it has been completed
	bool need_reconfirm;    // L7 protocol inference requiring confirmation.
	union {
		__u8  encoding_type;    // Currently used for OpenWire encoding inference.
		__s32 correlation_id;   // Currently used for Kafka protocol inference.
	};

	__u32 peer_fd;		// Used to record the peer fd for data transfer between sockets.

	/*
	 * This time is updated whenever there is data read/write. It
	 * represents the elapsed time in seconds from the system boot
	 * to the time of update.
	 */
	__u32 update_time;
	__u32 prev_data_len;
	__u64 trace_id;
	__u64 uid; // Unique identifier ID for the socket.
} __attribute__((packed));

struct kprobe_port_bitmap {
	__u8 bitmap[65536 / 8];
} __attribute__((packed));

struct trace_conf_t {
	__u64 socket_id;       // 会话标识
	__u64 coroutine_trace_id;  // 同一协程的数据转发关联
	__u64 thread_trace_id; // 同一进程/线程的数据转发关联，用于多事务流转场景
	__u32 data_limit_max;  // Maximum number of data transfers
	__u32 go_tracing_timeout;
	__u32 io_event_collect_mode;
	__u64 io_event_minimal_duration;
};

static __inline int infer_iovecs_copy(struct infer_data_s *infer_buf,
				      const struct data_args_t *args,
				      size_t syscall_len,
				      __u32 copy_len,
				      char **f_iov, __u32 * f_iov_len);

struct trace_key_t {
	__u32 tgid;
	__u32 pid;
	__u64 goid;
} __attribute__((packed));

struct trace_stats {
	__u64 socket_map_count;     // 对socket 链接表进行统计
	__u64 trace_map_count;     // 对同一进程/线程的多次转发表进行统计
};

/*
 * 整个结构大小为2^15（强制为2的次幂），目的是用（2^n - 1）与数据
 * 长度作位与操作使eBPF程序进行安全的bpf_perf_event_output()操作。
 */
struct __socket_data_buffer {
	__u32 events_num;
	__u32 len; // data部分长度
	char data[32760]; // 32760 + len(4bytes) + events_num(4bytes) = 2^15 = 32768
};

struct __socket_data {
	/* 进程/线程信息 */
	__u32 pid;  // 表示线程号 如果'pid == tgid'表示一个进程, 否则是线程
	__u32 tgid; // 进程号
	__u64 coroutine_id; // CoroutineID, i.e., golang goroutine id
	__u8 source; // SYSCALL,GO_TLS_UPROBE,GO_HTTP2_UPROBE
	__u8 comm[TASK_COMM_LEN]; // 进程或线程名

	/* 连接（socket）信息 */
	__u64 socket_id;     /* 通信socket唯一ID， 从启动时的时钟开始自增1 */
	struct __tuple_t tuple;

	/*
	 * 携带数据， 比如：MySQL第一次读取的数据，被第二次读取的数据携带一并发给用户
	 * 注意携带数据只有4字节大小。
	 */
	char extra_data[EBPF_CACHE_SIZE];
	__u32 extra_data_count;

	/* 追踪信息 */
	__u32 tcp_seq;
	__u64 thread_trace_id;

	/* 追踪数据信息 */
	__u64 timestamp;     // 数据捕获时间戳
	__u8 direction: 1;  // bits[0]: 方向，值为T_EGRESS(0), T_INGRESS(1)
	__u8 msg_type:  6;  // bits[1-6]: 信息类型，值为MSG_UNKNOWN(0), MSG_REQUEST(1), MSG_RESPONSE(2)
	__u8 is_tls: 1;

	__u64 syscall_len;   // 本次系统调用读、写数据的总长度
	__u64 data_seq;      // cap_data在Socket中的相对顺序号
	__u16 data_type;     // HTTP, DNS, MySQL
	__u16 data_len;      // 数据长度
	__u8  socket_role;   // this message is created by: 0:unkonwn 1:client(connect) 2:server(accept)
	char data[BURST_DATA_BUF_SIZE];
} __attribute__((packed));

struct trace_info_t {
	__u8  reserve;
	__u32 update_time; // 从系统开机开始到创建/更新时的间隔时间单位是秒
	__u32 peer_fd;	   // 用于socket之间的关联
	__u64 thread_trace_id; // 线程追踪ID
	__u64 socket_id; // Records the socket associated when tracing was created (记录创建追踪时关联的socket)
} __attribute__((packed));

#endif