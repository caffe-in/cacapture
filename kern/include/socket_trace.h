#include <vmlinux.h>
#include "common.h"

#define INFER_FINISH    0
#define INFER_CONTINUE	1
#define INFER_TERMINATE	2
#define DATA_BUF_MAX  32
#define SOCK_CHECK_TYPE_ERROR           0
#define SOCK_CHECK_TYPE_UDP             1
#define SOCK_CHECK_TYPE_TCP_ES          2
struct data_args_t {
	// Represents the function from which this argument group originates.
	enum syscall_src_func source_fn;
	__u32 fd;
	// For send()/recv()/write()/read().
	const char *buf;
	// For sendmsg()/recvmsg()/writev()/readv().
	const struct iovec *iov;
	size_t iovlen;
	union {
		// For sendmmsg()
		unsigned int *msg_len;
		// For clock_gettime()
		struct timespec *timestamp_ptr;
	};

	union {
		__u64 socket_id; // Use for socket close
		__u64 enter_ts;  // Timestamp for enter syscall function.
	};

	__u32 tcp_seq;		// Used to record the entry of syscalls
	union {
		ssize_t bytes_count;	// io event
		ssize_t data_seq;	// Use for socket close
	};
} __attribute__ ((packed));

struct syscall_comm_enter_ctx {
	__u64 __pad_0;		/*     0     8 */
	int __syscall_nr;	/*    offset:8     4 */
	__u32 __pad_1;		/*    12     4 */
	union {
		struct {
			__u64 fd;	/*  offset:16   8  */
			char *buf;	/*  offset:24   8  */
		};

		// For clock_gettime()
		struct {
			clockid_t which_clock;	/*   offset:16   8  */
			struct timespec *tp;	/*   offset:24   8  */
		};
	};
	size_t count;		/*    32     8 */
	unsigned int flags;
};
struct syscall_comm_exit_ctx {
	__u64 __pad_0;		/*     0     8 */
	int __syscall_nr;	/*    offset:8     4 */
	__u32 __pad_1;		/*    12     4 */
	__u64 ret;		/*    offset:16    8 */
};

struct process_data_extra {
	bool vecs:1;
	bool is_go_process:1;
	enum process_data_extra_source source;
	enum traffic_protocol protocol;
	__u64 coroutine_id;
	enum traffic_direction direction;
	enum message_type message_type;
} __attribute__ ((packed));

struct member_fields_offset {
	__u8 ready;
	__u32 task__files_offset;
	__u32 sock__flags_offset;
	__u32 tcp_sock__copied_seq_offset;
	__u32 tcp_sock__write_seq_offset;

	__u32 struct_files_struct_fdt_offset;	// offsetof(struct files_struct, fdt)
	__u32 struct_files_private_data_offset;	// offsetof(struct file, private_data)
	__u32 struct_file_f_inode_offset;	// offsetof(struct file, f_inode)
	__u32 struct_inode_i_mode_offset;	// offsetof(struct inode, i_mode)
	__u32 struct_file_dentry_offset;	// offsetof(struct file, f_path) + offsetof(struct path, dentry)
	__u32 struct_dentry_name_offset;	// offsetof(struct dentry, d_name) + offsetof(struct qstr, name)
	__u32 struct_sock_family_offset;	// offsetof(struct sock_common, skc_family)
	__u32 struct_sock_saddr_offset;	// offsetof(struct sock_common, skc_rcv_saddr)
	__u32 struct_sock_daddr_offset;	// offsetof(struct sock_common, skc_daddr)
	__u32 struct_sock_ip6saddr_offset;	// offsetof(struct sock_common, skc_v6_rcv_saddr)
	__u32 struct_sock_ip6daddr_offset;	// offsetof(struct sock_common, skc_v6_daddr)
	__u32 struct_sock_dport_offset;	// offsetof(struct sock_common, skc_dport)
	__u32 struct_sock_sport_offset;	// offsetof(struct sock_common, skc_num)
	__u32 struct_sock_skc_state_offset;	// offsetof(struct sock_common, skc_state)
	__u32 struct_sock_common_ipv6only_offset;	// offsetof(struct sock_common, skc_flags)

};

struct conn_info_s {
#ifdef PROBE_CONN
	__u64 id;
#endif
	struct __tuple_t tuple;
	__u16 skc_family;	/* PF_INET, PF_INET6... */
	__u16 sk_type;		/* socket type (SOCK_STREAM, etc) */
	__u8 skc_ipv6only:1;
	__u8 enable_reasm:1;	/* Is data restructuring allowed? */

	/*
	 * Whether the socket l7 protocol type needs
	 * to be confirmed again.
	 */
	__u8 need_reconfirm:1;
	/*
	 * Retain tracing information without deletion, primarily
	 * addressing scenarios where MySQL kComStmtClose/kComStmtQuit
	 * single-sided transmissions (client requests without responses)
	 * tracing gets interrupted.
	 */
	__u8 keep_trace:1;
	__u8 direction:1;	// current T_INGRESS or T_EGRESS
	__u8 prev_direction:1;	// The direction of the last saved data
	__u8 role:2;
	__u8 skc_state;
	/*
	 * Used to skip protocol checking when Linux 5.2+
	 * kernel protocol inference.
	 */
	__u8 skip_proto;
	/*
	   The matching logic is:

	   DNS 1 req ---->
	   DNS 1 res <-------
	   DNS 2 req ---->
	   DNS 2 res <-------

	   and now it is

	   DNS 1 req ---->
	   DNS 2 req ---->
	   DNS 1 res <-------
	   DNS 2 res <-------

	   Such a scene affects the whole tracking

	   DNS 1 req is IPV6, DNS 2 req is IPV4
	 */
	// FIXME: Remove this field when the call chain can correctly handle
	// the Go DNS case. Parse DNS save record type and ignore AAAA records
	// in call chain trace
	__u16 dns_q_type;

	__u32 fd;
	// The protocol of traffic on the connection (HTTP, MySQL, etc.).
	enum traffic_protocol protocol;
	// MSG_UNKNOWN, MSG_REQUEST, MSG_RESPONSE
	__u32 message_type: 4;
	// Is this segment of data reassembled?
	__u32 is_reasm_seg: 1;
	__u32 reserved: 27;

	union {
		__u8  encoding_type;    // Currently used for OpenWire encoding inference
		__s32 correlation_id;	// Currently used for Kafka determination
	};
	__u32 prev_count;	// Prestored data length
	__u32 syscall_infer_len;
	__u64 count:40;
	__u64 tcpseq_offset:24;
	char prev_buf[EBPF_CACHE_SIZE];
	char *syscall_infer_addr;
	void *sk;
	struct socket_info_s *socket_info_ptr;	/* lookup __socket_info_map */
};

struct __tuple_t {
	__u8 daddr[16];
	__u8 rcv_saddr[16];
	__u8 addr_len;
	__u8 l4_protocol;
	__u16 dport;
	__u16 num;
};

static __inline __u64 gen_conn_key_id(__u64 param_1, __u64 param_2)
{
	/*
	 * key:
	 *  - param_1 low 32bits as key high bits.
	 *  - param_2 low 32bits as key low bits.
	 */
	return ((param_1 << 32) | (__u32) param_2);
}

struct ctx_info_s {
	union {
		struct infer_data_s infer_buf;
		struct tail_calls_context tail_call;
	};
};

struct infer_data_s {
	__u32 len;
	char data[DATA_BUF_MAX * 2];
};

struct tail_calls_context {
	/*
	 * If it is a tail call in the protocol inference section,
	 * the stored data here includes the inference data cache
	 * and its length; other tail calls currently do not use
	 * private data.
	 */
	char private_data[sizeof(struct infer_data_s)];
	int max_size_limit;		// The maximum size of the socket data that can be transferred.
	__u32 push_reassembly_bytes;	// The number of bytes pushed after enabling data reassembly.
	enum traffic_direction dir;	// Data flow direction.
	__u8 vecs: 1;			// Whether a memory vector is used ? (for specific syscall)
	__u8 is_close: 1;		// Is it a close() systemcall ?
	__u8 reserve: 6;
	struct conn_info_s conn_info;
	struct process_data_extra extra;
	__u32 bytes_count;
	struct member_fields_offset *offset;
};