#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "include/socket_trace.h"
#include "maps.h"
#include "common.h"
#include "vmlinux_missing.h"
#include "include/bpf_endian.h"
#include "include/bpf_base.h"
#include "include/utils.h"
#include "include/protocol_inference.h"

#define SUBMIT_OK (0)
#define SUBMIT_INVALID (-1)
#define SUBMIT_ABORT (-2)

#define NS_PER_US 1000ULL
#define NS_PER_SEC 1000000000ULL

#define EVENT_BURST_NUM 16

#define ipv4_mapped_on_ipv6_confirm(s, f, o)                         \
	do                                                               \
	{                                                                \
		char __addr[16];                                             \
		bpf_probe_read_kernel(__addr, 16,                            \
							  (s) + o->struct_sock_ip6saddr_offset); \
		__u32 __feature = *(__u32 *)&__addr[8];                      \
		if (__feature == 0xffff0000)                                 \
			f = PF_INET;                                             \
	} while (0)
static __inline void get_sock_flags(void *sk,
									struct member_fields_offset *offset,
									struct conn_info_s *conn_info)
{
	struct sock_flags_t
	{
		unsigned int sk_padding : 1;
		unsigned int sk_kern_sock : 1;
		unsigned int sk_no_check_tx : 1;
		unsigned int sk_no_check_rx : 1;
		unsigned int sk_userlocks : 4;
		unsigned int sk_protocol : 8;
		unsigned int sk_type : 16;
	};

	unsigned int flags = 0;
	struct sock_flags_t *sk_flags = (struct sock_flags_t *)&flags;
	bpf_probe_read_kernel(&flags, sizeof(flags), (void *)sk + offset->sock__flags_offset);

	conn_info->sk_type = sk_flags->sk_type;
}
static __inline int is_tcp_udp_data(void *sk,
									struct member_fields_offset *offset,
									struct conn_info_s *conn_info)
{
	struct skc_flags_t
	{
		unsigned char skc_reuse : 4;
		unsigned char skc_reuseport : 1;
		unsigned char skc_ipv6only : 1;
		unsigned char skc_net_refcnt : 1;
	};

	struct skc_flags_t skc_flags;
	bpf_probe_read_kernel(&skc_flags, sizeof(skc_flags),
						  sk + offset->struct_sock_common_ipv6only_offset);
	conn_info->skc_ipv6only = skc_flags.skc_ipv6only;
	bpf_probe_read_kernel(&conn_info->skc_family,
						  sizeof(conn_info->skc_family),
						  sk + offset->struct_sock_family_offset);
	/*
	 * Without thinking about PF_UNIX.
	 */
	switch (conn_info->skc_family)
	{
	case PF_INET:
		break;
	case PF_INET6:
		if (conn_info->skc_ipv6only == 0)
		{
			ipv4_mapped_on_ipv6_confirm(sk, conn_info->skc_family,
										offset);
		}
		break;
	default:
		return SOCK_CHECK_TYPE_ERROR;
	}

	get_sock_flags(sk, offset, conn_info);

	if (conn_info->sk_type == SOCK_DGRAM)
	{
		conn_info->tuple.l4_protocol = IPPROTO_UDP;
		return SOCK_CHECK_TYPE_UDP;
	}

	if (conn_info->sk_type != SOCK_STREAM)
	{
		return SOCK_CHECK_TYPE_ERROR;
	}

	bpf_probe_read_kernel(&conn_info->skc_state,
						  sizeof(conn_info->skc_state),
						  (void *)sk +
							  offset->struct_sock_skc_state_offset);

	/*
	 * If the connection has not been established yet, and it is not in the
	 * ESTABLISHED or CLOSE_WAIT state, exit.
	 */
	if ((1 << conn_info->skc_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
	{
		return SOCK_CHECK_TYPE_ERROR;
	}

	conn_info->tuple.l4_protocol = IPPROTO_TCP;
	return SOCK_CHECK_TYPE_TCP_ES;
}

static __inline void init_conn_info(__u32 tgid, __u32 fd,
									struct conn_info_s *conn_info, void *sk,
									struct member_fields_offset *offset)
{
	__be16 inet_dport;
	__u16 inet_sport;
	bpf_probe_read_kernel(&inet_dport, sizeof(inet_dport),
						  sk + offset->struct_sock_dport_offset);
	bpf_probe_read_kernel(&inet_sport, sizeof(inet_sport),
						  sk + offset->struct_sock_sport_offset);
	conn_info->tuple.dport = __bpf_ntohs(inet_dport);
	conn_info->tuple.num = inet_sport;
	conn_info->correlation_id = -1; // 当前用于kafka,openwire协议推断
	conn_info->fd = fd;

	conn_info->sk = sk;
	__u64 conn_key = gen_conn_key_id((__u64)tgid, (__u64)conn_info->fd);
	conn_info->socket_info_ptr = socket_info_map__lookup(&conn_key);
}

/*
 * B : buffer
 * O : buffer offset, e.g.: infer_buf->len
 * I : &args->iov[i]
 * L_T : total_size
 * L_C : bytes_copy
 * F : first_iov
 * F_S : first_iov_size
 */
/* *INDENT-OFF* */
#define COPY_IOV(B, O, I, L_T, L_C, F, F_S)                                    \
	do                                                                         \
	{                                                                          \
		struct iovec iov_cpy;                                                  \
		bpf_probe_read_user(&iov_cpy, sizeof(struct iovec), (I));              \
		if (iov_cpy.iov_base == NULL || iov_cpy.iov_len == 0)                  \
			continue;                                                          \
		if (!(F))                                                              \
		{                                                                      \
			F = iov_cpy.iov_base;                                              \
			F_S = iov_cpy.iov_len;                                             \
		}                                                                      \
		const int bytes_remaining = (L_T) - (L_C);                             \
		__u32 iov_size =                                                       \
			iov_cpy.iov_len <                                                  \
					bytes_remaining                                            \
				? iov_cpy.iov_len                                              \
				: bytes_remaining;                                             \
		__u32 len = (O) + (L_C);                                               \
		struct copy_data_s *cp = (struct copy_data_s *)((B) + len);            \
		if (len > (sizeof((B)) - sizeof(*cp)))                                 \
			break;                                                             \
		if (iov_size >= sizeof(cp->data))                                      \
		{                                                                      \
			bpf_probe_read_user(cp->data, sizeof(cp->data), iov_cpy.iov_base); \
			iov_size = sizeof(cp->data);                                       \
		}                                                                      \
		else                                                                   \
		{                                                                      \
			iov_size = iov_size & (sizeof(cp->data) - 1);                      \
			bpf_probe_read_user(cp->data, iov_size + 1, iov_cpy.iov_base);     \
		}                                                                      \
		L_C = (L_C) + iov_size;                                                \
	} while (0)
/* *INDENT-ON* */

static __inline int infer_iovecs_copy(struct infer_data_s *infer_buf,
									  const struct data_args_t *args,
									  size_t syscall_len,
									  __u32 copy_len,
									  char **f_iov, __u32 *f_iov_len)
{
#define INFER_COPY_SZ 32
#define INFER_LOOP_LIMIT 4
	struct copy_data_s
	{
		char data[INFER_COPY_SZ];
	};

	int bytes_copy = 0;
	__u32 total_size = 0;
	infer_buf->len = 0;

	if (syscall_len >= sizeof(infer_buf->data))
		total_size = sizeof(infer_buf->data);
	else
		total_size = copy_len;

	if (total_size > syscall_len)
		total_size = syscall_len;

	char *first_iov = NULL;
	__u32 first_iov_size = 0;

#pragma unroll
	for (unsigned int i = 0;
		 i < INFER_LOOP_LIMIT && i < args->iovlen && bytes_copy < total_size; i++)
	{
		COPY_IOV(infer_buf->data, infer_buf->len, &args->iov[i],
				 total_size, bytes_copy, first_iov, first_iov_size);
	}

	*f_iov = first_iov;
	*f_iov_len = first_iov_size;

	return bytes_copy;
}

static __inline int
infer_l7_class(struct ctx_info_s *ctx,
			   struct conn_info_s *conn_info,
			   enum traffic_direction direction,
			   const struct data_args_t *args,
			   size_t bytes_count, __u8 sk_type,
			   const struct process_data_extra *extra)
{
	if (conn_info == NULL)
	{
		return INFER_TERMINATE;
	}
	struct protocol_message_t inferred_protocol =
		infer_protocol(ctx, args, bytes_count, conn_info, sk_type, extra);
	if (inferred_protocol.protocol == PROTO_UNKNOWN &&
		inferred_protocol.type == MSG_UNKNOWN)
	{
		conn_info->protocol = PROTO_UNKNOWN;
		return INFER_CONTINUE;
	}
}

static __inline int process_data(struct pt_regs *ctx, __u64 id,
								 const enum traffic_direction direction,
								 const struct data_args_t *args,
								 ssize_t bytes_count,
								 const struct process_data_extra *extra)
{
	if (!extra)
		return -1;

	if (!extra->vecs && args->buf == NULL)
		return -1;

	if (extra->vecs && (args->iov == NULL || args->iovlen <= 0))
		return -1;

	if (unlikely(args->fd < 0 || (int)bytes_count <= 0))
		return -1;
	// k0 the first key in bpf map, k1 the second key in bpf map. some map has only one or tow key
	__u32 k0 = 1, k1 = 1;
	// use offset to get member from socket info
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return -1;
	if (unlikely(!offset->ready))
		return -1;

	void *sk = get_socket_from_fd(args->fd, offset);
	struct conn_info_s *conn_info, __conn_info = {0};
	conn_info = &__conn_info;

	__u8 sock_state;
	if (!(sk != NULL &&
		  ((sock_state = is_tcp_udp_data(sk, offset, conn_info)) != SOCK_CHECK_TYPE_ERROR)))
	{
		return -1;
	}

	init_conn_info(id >> 32, args->fd, conn_info, sk, offset);

	conn_info->direction = direction;
	// ctx_info -> MAP_PERARRAY(ctx_info, __u32, struct ctx_info_s, 1) in include/map.h
	struct ctx_info_s *ctx_map = bpf_map_lookup_elem(&NAME(ctx_info), &k0);

	if (!ctx_map)
		return -1;

	struct kprobe_port_bitmap *bypass = kprobe_port_bitmap__lookup(&k1);
	if (bypass)
	{
		if (is_set_bitmap(bypass->bitmap, conn_info->tuple.dport) ||
			is_set_bitmap(bypass->bitmap, conn_info->tuple.num))
		{
			return -1;
		}
	}
	bool data_submit_dircet = false;
	struct kprobe_port_bitmap *allow = kprobe_port_bitmap__lookup(&k0);
	if (allow)
	{
		if (is_set_bitmap(allow->bitmap, conn_info->tuple.dport) ||
			is_set_bitmap(allow->bitmap, conn_info->tuple.num))
		{
			data_submit_dircet = true;
		}
	}
	if (data_submit_dircet)
	{
		conn_info->protocol = PROTO_ORTHER;
		conn_info->message_type = MSG_REQUEST;
	}
	else
	{
		int act;
		act = infer_l7_class(ctx_map, conn_info, direction, args,
							 bytes_count, sock_state, extra);

		if (act == INFER_CONTINUE)
		{
			ctx_map->tail_call.conn_info = __conn_info;
			ctx_map->tail_call.extra = *extra;
			ctx_map->tail_call.bytes_count = bytes_count;
			ctx_map->tail_call.offset = offset;
			ctx_map->tail_call.dir = direction;
			/* Enter the protocol inference tail call program. */
			if (extra->source == DATA_SOURCE_SYSCALL)
				bpf_tail_call(ctx, &NAME(progs_jmp_tp_map),
							  PROG_PROTO_INFER_TP_IDX);
			else
				bpf_tail_call(ctx, &NAME(progs_jmp_kp_map),
							  PROG_PROTO_INFER_KP_IDX);
		}
	}
}
static __inline void process_syscall_data(struct pt_regs *ctx, __u64 id,
										  const enum traffic_direction direction,
										  const struct data_args_t *args,
										  ssize_t bytes_count)
{
	struct process_data_extra extra = {
		.vecs = false,
		.source = DATA_SOURCE_SYSCALL,
		.is_go_process = false

	};
	if (!process_data(ctx, id, direction, args, bytes_count, &extra))
	{
		bpf_tail_call(ctx, &NAME(progs_jmp_tp_map),
					  PROG_DATA_SUBMIT_TP_IDX);
	}
	else
	{
		bpf_tail_call(ctx, &NAME(progs_jmp_tp_map),
					  PROG_IO_EVENT_TP_IDX);
	}
}

// =====================BPF PROBES=======================
SEC("tracepoint/syscalls/sys_enter_write")
int bpf_func_sys_enter_write(struct syscall_comm_enter_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	int fd = (int)ctx->fd;
	char *buf = (char *)ctx->buf;

	struct data_args_t write_args = {};
	write_args.source_fn = SYSCALL_FUNC_WRITE;
	write_args.fd = fd;
	write_args.buf = buf;
	write_args.enter_ts = bpf_ktime_get_ns();
	// write_args.tcp_seq = get_tcp_write_seq_from_fd(fd); what is the function of this statement?
	active_write_args_map__update(&id, &write_args);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int bpf_func_sys_exit_write(struct syscall_comm_exit_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	ssize_t bytes_count = ctx->ret;
	struct data_args_t *write_args = active_write_args_map__lookup(&id);
	if (write_args != NULL && write_args->fd > 2)
	{
		write_args->bytes_count = bytes_count;
		process_syscall_data((struct pt_regs *)ctx, id, T_EGRESS,
							 write_args, bytes_count);
	}
}

//==============================================================================================

SEC("prog/tp/__data_submit") int bpf_prog_tp__data_submit (void *ctx)
{
	int ret;
	ret = data_submit(ctx);
	if (ret == SUBMIT_OK)
	{
		bpf_tail_call(ctx, &NAME(progs_jmp_tp_map),
					  PROG_OUTPUT_DATA_TP_IDX);
	}
	else if (ret == SUBMIT_ABORT)
	{
		return 0;
	}
	else
	{
		bpf_tail_call(ctx, &NAME(progs_jmp_tp_map),
					  PROG_IO_EVENT_TP_IDX);
	}

	return 0;
}

SEC("prog/kp/__data_submit") int bpf_prog_kp__data_submit (void *ctx)
{
	int ret;
	ret = data_submit(ctx);
	if (ret == SUBMIT_OK)
	{
		bpf_tail_call(ctx, &NAME(progs_jmp_kp_map),
					  PROG_OUTPUT_DATA_KP_IDX);
	}
	else if (ret == SUBMIT_ABORT)
	{
		return 0;
	}
	else
	{
		__u64 id = bpf_get_current_pid_tgid();
		active_read_args_map__delete(&id);
		active_write_args_map__delete(&id);
	}

	return 0;
}
static __inline int data_submit(void *ctx)
{
	int ret = 0;
	__u32 k0 = 0;
	struct ctx_info_s *ctx_map = bpf_map_lookup_elem(&NAME(ctx_info), &k0);
	if (!ctx_map)
		return SUBMIT_ABORT;

	__u64 id = bpf_get_current_pid_tgid();
	struct conn_info_s *conn_info;
	struct conn_info_s __conn_info = ctx_map->tail_call.conn_info;
	conn_info = &__conn_info;
	__u64 conn_key = gen_conn_key_id(id >> 32, (__u64)conn_info->fd);
	conn_info->socket_info_ptr = socket_info_map__lookup(&conn_key);
	if (!conn_info->is_reasm_seg && conn_info->socket_info_ptr)
		conn_info->socket_info_ptr->finish_reasm = false;

	struct data_args_t *args;
	if (conn_info->direction == T_INGRESS)
		args = active_read_args_map__lookup(&id);
	else
		args = active_write_args_map__lookup(&id);

	if (args == NULL)
		return SUBMIT_ABORT;

	const bool vecs = ctx_map->tail_call.extra.vecs;
	__u32 bytes_count = ctx_map->tail_call.bytes_count;
	struct member_fields_offset *offset = ctx_map->tail_call.offset;
	__u64 enter_ts = args->enter_ts;
	const struct process_data_extra extra = ctx_map->tail_call.extra;

	ret = __data_submit(ctx, conn_info, args, vecs, bytes_count,
						offset, enter_ts, &extra);

	return ret;
}

static __inline struct trace_key_t get_trace_key(__u64 timeout,
												 bool is_socket_io)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 goid = 0;

	if (timeout)
	{
		goid = get_rw_goid(timeout * NS_PER_SEC, is_socket_io);
	}

	struct trace_key_t key = {};

	key.tgid = (__u32)(pid_tgid >> 32);

	if (goid)
	{
		key.goid = goid;
	}
	else
	{
		key.pid = (__u32)pid_tgid;
	}

	return key;
}
static __inline int
__data_submit(struct pt_regs *ctx, struct conn_info_s *conn_info,
			  const struct data_args_t *args, const bool vecs,
			  __u32 syscall_len, struct member_fields_offset *offset,
			  __u64 time_stamp, const struct process_data_extra *extra)
{
	if (conn_info == NULL)
	{
		return SUBMIT_INVALID;
	}

	if (conn_info->sk == NULL || conn_info->message_type == MSG_UNKNOWN)
	{
		return SUBMIT_INVALID;
	}

	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u64 conn_key = gen_conn_key_id((__u64)tgid, (__u64)conn_info->fd);

	if (conn_info->message_type == MSG_CLEAR)
	{
		delete_socket_info(conn_key, conn_info->socket_info_ptr);
		return SUBMIT_INVALID;
	}

	__u32 tcp_seq = args->tcp_seq;
	__u64 thread_trace_id = 0;
	__u32 k0 = 0;
	struct socket_info_s sk_info = {0};
	struct trace_conf_t *trace_conf = trace_conf_map__lookup(&k0);
	if (trace_conf == NULL)
		return SUBMIT_INVALID;

	/*
	 * It is possible that these values were modified during ebpf running,
	 * so they are saved here.
	 */
	int data_max_sz = trace_conf->data_limit_max;

	struct trace_stats *trace_stats = trace_stats_map__lookup(&k0);
	if (trace_stats == NULL)
		return SUBMIT_INVALID;

	struct trace_key_t trace_key =
		get_trace_key(trace_conf->go_tracing_timeout,
					  true);
	struct trace_info_t *trace_info_ptr = trace_map__lookup(&trace_key);

	struct socket_info_s *socket_info_ptr = conn_info->socket_info_ptr;
	// 'socket_id' used to resolve non-tracing between the same socket
	__u64 socket_id = 0;
	if (!is_socket_info_valid(socket_info_ptr))
	{
		// Not use "++trace_conf->socket_id" here,
		// because it did not pass the verification of linux 4.14.x, 4.15.x
		socket_id = trace_conf->socket_id + 1;
	}
	else
	{
		socket_id = socket_info_ptr->uid;
	}

#define DNS_AAAA_TYPE_ID 0x1c
	// FIXME: By default, the Go process continuously sends A record and
	// AAAA record DNS request messages. In the current call chain tracking
	// implementation, two consecutive request messages before receiving
	// the response message will cause the link to be broken. Ignore the
	// AAAA record To ensure that the call chain will not be broken.
	if (conn_info->message_type != MSG_PRESTORE &&
		conn_info->message_type != MSG_RECONFIRM &&
		(trace_conf->go_tracing_timeout != 0 || extra->is_go_process == false) && !(conn_info->protocol == PROTO_DNS && conn_info->dns_q_type == DNS_AAAA_TYPE_ID))
		trace_process(socket_info_ptr, conn_info, socket_id,
					  bpf_get_current_pid_tgid(), trace_info_ptr,
					  trace_conf, trace_stats, &thread_trace_id,
					  time_stamp, &trace_key);

	if (!is_socket_info_valid(socket_info_ptr))
	{
		if (socket_info_ptr && conn_info->direction == T_EGRESS)
		{
			sk_info.peer_fd = socket_info_ptr->peer_fd;
			thread_trace_id = socket_info_ptr->trace_id;
		}

		sk_info.uid = trace_conf->socket_id + 1;
		trace_conf->socket_id++; // Ensure that socket_id is incremented.
		sk_info.l7_proto = conn_info->protocol;
		// Confirm whether data reassembly is required for this socket.
		if (is_proto_reasm_enabled(conn_info->protocol))
		{
			sk_info.allow_reassembly = true;
			sk_info.reasm_bytes =
				syscall_len >
						data_max_sz
					? data_max_sz
					: syscall_len;
		}
		sk_info.direction = conn_info->direction;
		sk_info.pre_direction = conn_info->direction;
		sk_info.role = conn_info->role;
		sk_info.update_time = time_stamp / NS_PER_SEC;
		sk_info.need_reconfirm = conn_info->need_reconfirm;
		sk_info.correlation_id = conn_info->correlation_id;

		/*
		 * MSG_PRESTORE 目前只用于MySQL, Kafka协议推断
		 */
		if (conn_info->message_type == MSG_PRESTORE)
		{
			bpf_probe_read_kernel(sk_info.prev_data,
								  sizeof(sk_info.prev_data),
								  conn_info->prev_buf);
			sk_info.prev_data_len = conn_info->prev_count;
			sk_info.uid = 0;
		}

		int ret = socket_info_map__update(&conn_key, &sk_info);
		if (socket_info_ptr == NULL && ret == 0)
		{
			__sync_fetch_and_add(&trace_stats->socket_map_count, 1);
		}
	}

	/*
	 * 对于预先存储数据或socket l7协议类型需要再次确认(适用于长链接)
	 * 的动作只建立socket_info_map项不会发送数据给用户态程序。
	 */
	if (conn_info->message_type == MSG_PRESTORE ||
		conn_info->message_type == MSG_RECONFIRM)
		return SUBMIT_INVALID;

	struct __socket_data_buffer *v_buff =
		bpf_map_lookup_elem(&NAME(data_buf), &k0);
	if (!v_buff)
		return SUBMIT_INVALID;

	struct __socket_data *v = (struct __socket_data *)&v_buff->data[0];

	if (v_buff->len > (sizeof(v_buff->data) - sizeof(*v)))
		return SUBMIT_INVALID;

	v = (struct __socket_data *)(v_buff->data + v_buff->len);
	if (get_socket_info(v, conn_info->sk, conn_info) == false)
		return SUBMIT_INVALID;

	__u32 send_reasm_bytes = 0;
	if (is_socket_info_valid(socket_info_ptr))
	{
		sk_info.uid = socket_info_ptr->uid;
		sk_info.allow_reassembly = socket_info_ptr->allow_reassembly;

		/*
		 * The kernel syscall interface determines that it is the TLS
		 * handshake protocol, and for the uprobe program, it needs to
		 * be re inferred to determine the upper layer protocol of TLS.
		 */
		if (socket_info_ptr->l7_proto == PROTO_TLS ||
			socket_info_ptr->l7_proto == PROTO_UNKNOWN)
			socket_info_ptr->l7_proto = conn_info->protocol;

		/*
		 * Ensure that the accumulation operation of capturing the
		 * data sequence number is an atomic operation when multiple
		 * threads read/write to the socket simultaneously.
		 */
		__sync_fetch_and_add(&socket_info_ptr->seq, 1);
		sk_info.seq = socket_info_ptr->seq;
		socket_info_ptr->direction = conn_info->direction;
		socket_info_ptr->update_time = time_stamp / NS_PER_SEC;
		if (socket_info_ptr->peer_fd != 0 && conn_info->direction == T_INGRESS)
		{
			__u64 peer_conn_key = gen_conn_key_id((__u64)tgid,
												  (__u64)
													  socket_info_ptr->peer_fd);
			struct socket_info_s *peer_socket_info_ptr =
				socket_info_map__lookup(&peer_conn_key);
			if (is_socket_info_valid(peer_socket_info_ptr))
				peer_socket_info_ptr->trace_id =
					thread_trace_id;
		}

		if (conn_info->direction == T_EGRESS && socket_info_ptr->trace_id != 0)
		{
			thread_trace_id = socket_info_ptr->trace_id;
			socket_info_ptr->trace_id = 0;
		}

		if (!conn_info->is_reasm_seg)
			socket_info_ptr->reasm_bytes = 0;

		/*
		 * Below, confirm the actual size of the data to be transmitted after
		 * enabling data reassembly. The data transmission size is limited by
		 * the maximum transmission configuration value.
		 */
		if (sk_info.allow_reassembly && socket_info_ptr->reasm_bytes < data_max_sz)
		{
			__u32 remain_bytes =
				data_max_sz - socket_info_ptr->reasm_bytes;
			send_reasm_bytes =
				(syscall_len >
						 remain_bytes
					 ? remain_bytes
					 : syscall_len);
			socket_info_ptr->reasm_bytes += send_reasm_bytes;
		}
	}

	v->tuple.l4_protocol = conn_info->tuple.l4_protocol;
	v->tuple.dport = conn_info->tuple.dport;
	v->tuple.num = conn_info->tuple.num;
	v->data_type = conn_info->protocol;

	__u32 *socket_role = socket_role_map__lookup(&conn_key);
	v->socket_role = socket_role ? *socket_role : 0;
	v->socket_id = sk_info.uid;
	v->data_seq = sk_info.seq;
	v->tgid = tgid;
	v->is_tls = false;
	v->pid = (__u32)bpf_get_current_pid_tgid();

	// For blocking reads, there is a significant deviation between the
	// entry time of the system call and the real time of the read
	// operation. Therefore, the end time of the system call is used for
	// the read operation.
	v->timestamp = conn_info->direction == T_INGRESS ? bpf_ktime_get_ns() : time_stamp;
	v->direction = conn_info->direction;
	v->syscall_len = syscall_len;
	v->msg_type = conn_info->message_type;

	// Reassembly modification type
	if (sk_info.allow_reassembly)
	{
		v->msg_type = MSG_REASM_START;
		if (conn_info->is_reasm_seg)
			v->msg_type = MSG_REASM_SEG;
		else
			send_reasm_bytes = 0;
	}
	v->tcp_seq = 0;

	if ((extra->source == DATA_SOURCE_GO_TLS_UPROBE ||
		 extra->source == DATA_SOURCE_OPENSSL_UPROBE) ||
		(conn_info->tuple.l4_protocol == IPPROTO_TCP))
	{
		/*
		 * If the current state is TCPF_CLOSE_WAIT, the FIN frame already has been received.
		 * However, it cannot be confirmed that it has been processed by the syscall,
		 * so use the tcp_seq value that entering the syscalls.
		 *
		 * Why not use "v->tcp_seq = args->tcp_seq;" ?
		 * This is because kernel 4.14 verify reports errors("R0 invalid mem access 'inv'").
		 */
		v->tcp_seq = tcp_seq;
	}

	v->thread_trace_id = thread_trace_id;
	bpf_get_current_comm(v->comm, sizeof(v->comm));

	if (conn_info->tuple.l4_protocol == IPPROTO_TCP &&
		conn_info->protocol == PROTO_DNS && conn_info->prev_count == 2)
	{
		v->tcp_seq -= 2;
		conn_info->prev_count = 0;
	}

	/*
	 * Due to differences in the data captured through the `af_packet` and
	 * `eBPF methods` for HTTP/2, for example:
	 * - Data captured using the af_packet method:
	 *   `PING[0], HEADERS[86125]: 200 OK, DATA[86125]`
	 * - Data captured using the eBPF method:
	 *   `HEADERS[86125]: 200 OK, DATA[86125]`
	 *
	 * Furthermore, both sides are unaware of the differences in the captured data.
	 * This inconsistency can lead to inconsistent `tcpseq` values, making it chal-
	 * lenging to correlate the data. To address this issue, it is agreed that both
	 * methods adjust the `tcpseq` to the starting position of the first `HEADER`.
	 */
	if (conn_info->protocol == PROTO_HTTP2)
		v->tcp_seq += conn_info->tcpseq_offset;

	if (conn_info->prev_count > 0)
	{
		// 注意这里没有调整v->syscall_len和v->len我们会在用户层做。
		bpf_probe_read_kernel(v->extra_data, sizeof(v->extra_data),
							  conn_info->prev_buf);
		v->extra_data_count = conn_info->prev_count;
		v->tcp_seq -= conn_info->prev_count; // 客户端和服务端的tcp_seq匹配
	}
	else
		v->extra_data_count = 0;

	v->coroutine_id = trace_key.goid;
	v->source = extra->source;

#ifdef LINUX_VER_5_2_PLUS
	__u32 cache_key = ((__u32)bpf_get_current_pid_tgid()) >> 16;
	if (cache_key < PROTO_INFER_CACHE_SIZE)
	{
		struct proto_infer_cache_t *p;
		p = proto_infer_cache_map__lookup(&cache_key);
		if (p)
		{
			__u16 idx = (__u16)bpf_get_current_pid_tgid();
			p->protocols[idx] = (__u8)v->data_type;
		}
	}
#endif

	struct tail_calls_context *context =
		(struct tail_calls_context *)v->data;
	context->max_size_limit = data_max_sz;
	context->push_reassembly_bytes = send_reasm_bytes;
	context->vecs = (bool)vecs;
	context->is_close = false;
	context->dir = conn_info->direction;

	return SUBMIT_OK;
}

SEC("prog/tp/__output_data") int bpf_prog_tp__output_data (void *ctx)
{
	return output_data_common(ctx);
}

SEC("prog/kp/__output_data") int bpf_prog_kp__output_data (void *ctx)
{
	return output_data_common(ctx);
}

/*
 * This eBPF program is specially used to transmit data to the agent. The purpose
 * of this is to solve the problem that the number of instructions exceeds the limit.
 */
static __inline int output_data_common(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	enum traffic_direction dir;
	bool vecs = false;
	int max_size = 0;
	bool is_close = false;
	__u32 k0 = 0;
	char *buffer = NULL;
	__u32 reassembly_bytes = 0;

	struct __socket_data_buffer *v_buff =
		bpf_map_lookup_elem(&NAME(data_buf), &k0);
	if (!v_buff)
		goto clear_args_map_2;

	struct tail_calls_context *context =
		(struct tail_calls_context *)(v_buff->data + v_buff->len +
									  offsetof(typeof(struct __socket_data),
											   data));

	if ((v_buff->len + offsetof(typeof(struct __socket_data), data) +
		 sizeof(struct tail_calls_context)) > sizeof(v_buff->data))
	{
		goto clear_args_map_2;
	}

	dir = context->dir;
	vecs = context->vecs;
	is_close = context->is_close;
	max_size = context->max_size_limit;
	reassembly_bytes = context->push_reassembly_bytes;

	struct data_args_t *args;
	if (dir == T_INGRESS)
		args = active_read_args_map__lookup(&id);
	else
		args = active_write_args_map__lookup(&id);

	if (args == NULL)
		goto clear_args_map_1;

	struct __socket_data *v =
		(struct __socket_data *)(v_buff->data + v_buff->len);
	if (v_buff->len > (sizeof(v_buff->data) - sizeof(*v)))
		goto clear_args_map_1;

	if (is_close)
	{
		v->data_len = 0;
		goto skip_copy;
	}

	if (v->source == DATA_SOURCE_IO_EVENT)
	{
		buffer = (char *)io_event_buffer__lookup(&k0);
		if (buffer == NULL)
		{
			goto clear_args_map_1;
		}
	}
	else
	{
		buffer = (char *)args->buf;
	}

	__u32 __len = v->syscall_len > max_size ? max_size : v->syscall_len;

	/*
	 * If data reassembly is enabled, the amount of data pushed must not
	 * exceed the reassembly transmission limit.
	 */
	if (reassembly_bytes > 0)
		__len = reassembly_bytes;

	/*
	 * the bitwise AND operation will set the range of possible values for
	 * the UNKNOWN_VALUE register to [0, BUFSIZE)
	 */
	__u32 len = __len & (sizeof(v->data) - 1);

	if (vecs)
	{
		len = iovecs_copy(v, v_buff, args, v->syscall_len, len);
	}
	else
	{
		if (__len >= sizeof(v->data))
		{
			if (v->source != DATA_SOURCE_IO_EVENT)
			{
				if (unlikely(bpf_probe_read_user(v->data, sizeof(v->data), buffer) != 0))
					goto clear_args_map_1;
			}
			else
			{
				if (unlikely(bpf_probe_read_kernel(v->data, sizeof(v->data), buffer) != 0))
					goto clear_args_map_1;
			}
			len = sizeof(v->data);
		}
		else
		{
			/*
			 * https://elixir.bootlin.com/linux/v4.14/source/kernel/bpf/verifier.c#812
			 * __check_map_access() 触发条件检查（size <= 0）
			 * ```
			 *     if (off < 0 || size <= 0 || off + size > map->value_size)
			 * ```
			 * "invalid access to map value, value_size=10888 off=135 size=0"
			 * 使用'len + 1'代替'len'，来规避（Linux 4.14.x）这个检查。
			 */
			if (v->source != DATA_SOURCE_IO_EVENT)
			{
				if (unlikely(bpf_probe_read_user(v->data,
												 len + 1,
												 buffer) != 0))
					goto clear_args_map_1;
			}
			else
			{
				if (unlikely(bpf_probe_read_kernel(v->data,
												   len + 1,
												   buffer) !=
							 0))
					goto clear_args_map_1;
			}
		}
	}

	v->data_len = len;

skip_copy:
	v_buff->len +=
		offsetof(typeof(struct __socket_data), data) + v->data_len;
	v_buff->events_num++;

	if (v_buff->events_num >= EVENT_BURST_NUM ||
		((sizeof(v_buff->data) - v_buff->len) < sizeof(*v)))
	{
		__u32 buf_size =
			(v_buff->len +
			 offsetof(typeof(struct __socket_data_buffer), data)) &
			(sizeof(*v_buff) - 1);
		/*
		 * Note that when 'buf_size == 0', it indicates that the data being
		 * sent is at its maximum value (sizeof(*v_buff)), and it should
		 * be sent accordingly.
		 */
		if (buf_size < sizeof(*v_buff) && buf_size > 0)
		{
			/*
			 * Use 'buf_size + 1' instead of 'buf_size' to circumvent
			 * (Linux 4.14.x) length checks.
			 */
			bpf_perf_event_output(ctx, &NAME(socket_data),
								  BPF_F_CURRENT_CPU, v_buff,
								  buf_size + 1);
		}
		else
		{
			bpf_perf_event_output(ctx, &NAME(socket_data),
								  BPF_F_CURRENT_CPU, v_buff,
								  sizeof(*v_buff));
		}

		v_buff->events_num = 0;
		v_buff->len = 0;
	}

clear_args_map_1:
	if (dir == T_INGRESS)
		active_read_args_map__delete(&id);
	else
		active_write_args_map__delete(&id);

	return 0;

clear_args_map_2:
	active_read_args_map__delete(&id);
	active_write_args_map__delete(&id);
	return 0;
}
