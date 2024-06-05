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

static __inline int
infer_l7_class(struct ctx_info_s *ctx,
		 struct conn_info_s *conn_info,
		 enum traffic_direction direction,
		 const struct data_args_t *args,
		 size_t bytes_count, __u8 sk_type,
		 const struct process_data_extra *extra)
{
    if(conn_info==NULL){
        return INFER_TERMINATE;
    }
    struct protocol_message_t inferred_protocol = 
        infer_protocol(ctx,args,bytes_count,conn_info,sk_type,extra);
	if (inferred_protocol.protocol == PROTO_UNKNOWN &&
	    inferred_protocol.type == MSG_UNKNOWN) {
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
    if (data_submit_dircet) {
		conn_info->protocol = PROTO_ORTHER;
		conn_info->message_type = MSG_REQUEST;
	} else {
		int act;
		act = infer_l7_class(ctx_map, conn_info, direction, args,
				       bytes_count, sock_state, extra);

		if (act == INFER_CONTINUE) {
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
        return;
    }
    else
    {
        return;
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
    active_write_args_map__update(&id, &write_args, BPF_ANY);
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
