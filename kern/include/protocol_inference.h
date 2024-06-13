
#ifndef DF_BPF_PROTO_INFER_H
#define DF_BPF_PROTO_INFER_H

#include "common.h"
#include "socket_trace.h"
#include "socket_trace_common.h"
#include "maps.h"
#include "bpf_endian.h"


#define LINUX_VER_5_2_PLUS 1
#define L7_PROTO_INFER_PROG	0
#define PROTO_INFER_CACHE_SIZE  80

typedef struct __attribute__ ((packed)) {
	__u8 content_type;
	__u16 version;
	__u16 length;
	__u8 handshake_type;
} tls_handshake_t;
static __inline bool is_socket_info_valid(struct socket_info_s *sk_info)
{
	return (sk_info != NULL && sk_info->uid != 0);
}


// When calling this function, count must be a constant, and at this time, the
// compiler can optimize it into an immediate value and write it into the
// instruction.
static __inline void save_prev_data_from_kern(const char *buf,
					      struct conn_info_s *conn_info,
					      size_t count)
{
	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		bpf_probe_read_kernel(conn_info->socket_info_ptr->prev_data,
				      count, buf);

		conn_info->socket_info_ptr->prev_data_len = count;
		/*
		 * This piece of data needs to be merged with subsequent data, so
		 * the direction of the previous piece of data needs to be saved here.
		 *
		 * For example:
		 * A  --> out
		 * B1 <-- in
		 * B2 <-- in
		 *
		 * The data of 'B1' and 'B2' will be merged into a single data stream,
		 * meaning that the data from B1 will be merged into 'B2' for transmission.
		 * Therefore, the direction of the previously merged data from B2 will be
		 * the same as the direction of 'A' (out), rather than the direction of 'B1'.
		 * This is saved using 'pre_direction'.
		 */
		conn_info->socket_info_ptr->pre_direction =
		    conn_info->socket_info_ptr->direction;
		conn_info->socket_info_ptr->direction = conn_info->direction;
	} else {
		bpf_probe_read_kernel(conn_info->prev_buf, count, buf);
		conn_info->prev_count = count;
	}
}


static __inline bool drop_msg_by_comm(void)
{
	char comm[TASK_COMM_LEN];

	if (bpf_get_current_comm(&comm, sizeof(comm)))
		return false;

	// filter 'ssh', 'scp', 'sshd'
	if (comm[0] == 's')
	{
		if ((comm[1] == 's' && comm[2] == 'h' && comm[3] == '\0') ||
			(comm[1] == 'c' && comm[2] == 'p' && comm[3] == '\0') ||
			(comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd' &&
			 comm[4] == '\0'))
			return true;
	}

	return false;
}

static __inline bool is_infer_socket_valid(struct socket_info_s *sk_info)
{
	/*
	 * Since the kernel collects TLS handshake data, the socket type is set
	 * to 'PROTO_TLS' during this process. UPROBE-collected TLS plaintext data
	 * needs to be re-evaluated, so here we specify that a socket type of
	 * 'PROTO_TLS' is invalid and requires re-evaluation.
	 *
	 * Additionally, 'PROTO_UNKNOWN' also needs to be re-evaluated. This situation
	 * is common when pre-storing some data, which establishes socket information
	 * but sets 'l7_proto' to 'PROTO_UNKNOWN'. The data needs to be combined with
	 * the next segment to be re-evaluated as a whole.
	 */
	return (sk_info != NULL && sk_info->uid != 0
		&& sk_info->l7_proto != PROTO_TLS
		&& sk_info->l7_proto != PROTO_UNKNOWN);
}
static __inline void check_and_fetch_prev_data(struct conn_info_s *conn_info)
{
	if (conn_info->socket_info_ptr != NULL &&
	    conn_info->socket_info_ptr->prev_data_len > 0) {
		/*
		 * For adjacent read/write in the same direction.
		 */
		if (conn_info->direction ==
		    conn_info->socket_info_ptr->direction) {
			bpf_probe_read_kernel(conn_info->prev_buf,
					      sizeof(conn_info->prev_buf),
					      conn_info->
					      socket_info_ptr->prev_data);
			conn_info->prev_count =
			    conn_info->socket_info_ptr->prev_data_len;
			/*
			 * When data is merged, that is, when two or more data with the same
			 * direction are merged together and processed as one data, the previously
			 * saved direction needs to be restored.
			 * 
			 * At the beginning of the inference stage, 'socket_info_ptr->direction'
			 * represents the direction of the previously sent data. During the final
			 * data transmission stage, it will be updated to reflect the direction of
			 * the current data.
			 */
			conn_info->socket_info_ptr->direction =
			    conn_info->socket_info_ptr->pre_direction;
		}

		/*
		 * Clean up previously stored data.
		 */
		conn_info->socket_info_ptr->prev_data_len = 0;
	}

}
static __inline void check_and_set_data_reassembly(struct conn_info_s
						   *conn_info)
{
	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		conn_info->prev_direction =
		    conn_info->socket_info_ptr->direction;
		if (conn_info->socket_info_ptr->finish_reasm)
			return;

		/*
		 * If data reassembly is enabled, subsequent contiguous data of the
		 * same direction will be pushed until the data changes direction or
		 * reaches the maximum data limit ('trace_conf->data_limit_max').
		 *
		 * In the initial stage of data protocol inference, determine and
		 * confirm whether data reassembly needs to be continued.
		 */
		if (conn_info->socket_info_ptr->allow_reassembly) {
			if (conn_info->prev_direction == conn_info->direction) {
				conn_info->enable_reasm = true;
				__u32 k0 = 0;
				struct trace_conf_t *trace_conf =
				    trace_conf_map__lookup(&k0);
				if (trace_conf == NULL)
					return;
				/*
				 * Here, the length is checked, and if it has already reached
				 * the configured limit, assembly will not proceed.
				 *
				 * Additionally, if the current data and the previous data are in
				 * the process of being merged (meaning these two pieces of data
				 * need to be combined into one, which we refer to as data merging),
				 * the data reassembly function will not be initiated at this time.
				 * This is because data reassembly is completed at a higher level,
				 * while data merging is performed at the eBPF layer. We need to wait
				 * for the data merging to complete before deciding whether data
				 * reassembly is needed (whether to decide to push to the upper layer
				 * for reassembly).
				 */
				if (conn_info->socket_info_ptr->reasm_bytes >=
				    trace_conf->data_limit_max
				    || conn_info->prev_count > 0)
					conn_info->enable_reasm = false;
			} else {
				conn_info->enable_reasm = false;
			}
		}
	}
}

static __inline bool is_protocol_enabled(int protocol)
{
	int *enabled = protocol_filter__lookup(&protocol);
	return (enabled) ? (*enabled) : (0);
}

static __inline bool is_set_ports_bitmap(ports_bitmap_t * ports, __u16 port)
{
	/* 
	 * Avoid using the form `ports->bitmap[port >> 3]` to index the
	 * bitmap, as it may lead to the following error:
	 *
	 *   115: (85) call bpf_map_lookup_elem#1
	 *   116: (15) if r0 == 0x0 goto pc+5
	 *   117: (79) r1 = *(u64 *)(r10 -168)
	 *   118: (77) r1 >>= 3
	 *   119: (0f) r0 += r1
	 *   120: (71) r1 = *(u8 *)(r0 +0)
	 *   R0 unbounded memory access, make sure to bounds check any array
	 *   access into a map
	 *
	 * The error message indicates that we need to perform boundary checks
	 * for R0.
	 */
	const __u8 *end = (const __u8*)ports + sizeof(*ports);
	const __u8 *start = (__u8 *) ports;
	const __u8 *addr = start + (port >> 3);
	if (addr >= start && addr < end) {
		/*
		 * Here, we must restrict the type of 'mask' to 'u8'; otherwise,
		 * when compiling as 'u64,' errors will occur upon loading the
		 * program:
		 *
		 *   122: (3d) if r1 >= r0 goto pc+6
		 *   123: (79) r2 = *(u64 *)(r10 -168)
		 *   124: (57) r2 &= 7
		 *   125: (71) r1 = *(u8 *)(r1 +0)
		 *   R1 unbounded memory access, make sure to bounds check any
		 *   array access into a map
		 */
		const __u8 mask = 1 << (port & 0x7);
		if (*addr & mask)
			return true;
	}

	return false;
}
#define is_set_bitmap(M, V)	\
	((M)[(((V) >> __builtin_popcount((sizeof(__typeof__((M)[0])) << 3) - 1)) & (sizeof((M)) - 1))] & (1 << ((V) & ((sizeof(__typeof__((M)[0])) << 3) - 1))))

static __inline bool
__protocol_port_check(enum traffic_protocol proto,
		      struct conn_info_s *conn_info, __u8 prog_num)
{
	if (!is_protocol_enabled(proto)) {
		return false;
	}

	__u32 key = proto;
	ports_bitmap_t *ports = proto_ports_bitmap__lookup(&key);
	if (ports) {
		/*
		 * If the "is_set_ports_bitmap()" function is used in both stages,
		 * there may be the following error when loading an eBPF program in
		 * the 4.14 kernel:
		 * `failed. name: bpf_func_sys_exit_sendmmsg, Argument list too long errno: 7`
		 * To avoid this situation, it is necessary to differentiate the calls.
		 */
		if (prog_num == L7_PROTO_INFER_PROG) {
			if (is_set_bitmap(ports->bitmap, conn_info->tuple.num)
			    || is_set_bitmap(ports->bitmap,
					     conn_info->tuple.dport))
				return true;
		} else {
			if (is_set_ports_bitmap(ports, conn_info->tuple.num) ||
			    is_set_ports_bitmap(ports, conn_info->tuple.dport))
				return true;
		}
	}

	return false;
}

static __inline bool
protocol_port_check(enum traffic_protocol proto,
		      struct conn_info_s *conn_info)
{
	return __protocol_port_check(proto, conn_info, L7_PROTO_INFER_PROG);
}

static __inline enum message_type
infer_tls_message(const char *buf, size_t count, struct conn_info_s *conn_info)
{
	/*
	 * When reading data over TLS, it first reads 5 bytes of content and then
	 * reads the remaining data. We save the initial 5 bytes and combine them
	 * with the subsequently read data. Then, we use the combined data for
	 * further processing.
	 */
	static const int advance_bytes = 5;

	tls_handshake_t handshake = { 0 };

	if (conn_info->prev_count == advance_bytes)
		count += advance_bytes;

	if (count == advance_bytes) {
		handshake.content_type = buf[0];
		handshake.version = __bpf_ntohs(*(__u16 *) & buf[1]);
		goto check;
	}
	// content type: ChangeCipherSpec(0x14) minimal length is 6
	if (count < 6)
		return MSG_UNKNOWN;

	if (conn_info->prev_count == advance_bytes) {
		handshake.content_type = conn_info->prev_buf[0];
		handshake.version =
		    __bpf_ntohs(*(__u16 *) & conn_info->prev_buf[1]);
		handshake.handshake_type = buf[0];

	} else {
		handshake.content_type = buf[0];
		handshake.version = __bpf_ntohs(*(__u16 *) & buf[1]);
		handshake.handshake_type = buf[5];
	}

check:
	/*
	 * Content Type:
	 * Handshake (0x16); Change Cipher Spec (0x14); Encrypted Alert (0x15)
	 */
	if (!(handshake.content_type == 0x16 ||
	      handshake.content_type == 0x14 || handshake.content_type == 0x15))
		return MSG_UNKNOWN;

	/* 
	 * version check:
	 *   0x0301 for TLS 1.0;
	 *   0x0302 for TLS 1.1;
	 *   0x0303 for TLS 1.2;
	 *   0x0304 for TLS 1.3;
	 */
	if (!(handshake.version >= 0x301 && handshake.version <= 0x304))
		return MSG_UNKNOWN;

	if (count == advance_bytes) {
		save_prev_data_from_kern(buf, conn_info, advance_bytes);
		return MSG_PRESTORE;
	}

	/*
	 * Encrypted Alert unidirectional transmission, retain tracking information
	 * without removal.
	 */
	if (handshake.content_type == 0x15)
		conn_info->keep_trace = 1;

	if (is_socket_info_valid(conn_info->socket_info_ptr)) {
		/* If it has been completed, give up collecting subsequent data. */
		if (handshake.content_type != 0x15 &&
		    conn_info->socket_info_ptr->tls_end)
			return MSG_UNKNOWN;
	}

	/*
	 * The following describes the read and write behavior of the
	 * system calls:
	 *
	 * client send:
	 * --------------
	 * (1) handshake_type 0x1 (client hello)
	 *
	 * client recv:
	 * --------------
	 * (2) handshake_type 0x2 (server hello)
	 * (3) handshake_type 0xb (certificates)
	 * (4) handshake_type 0xc (server key exchange message)
	 * (5) handshake_type 0xe (server hello done message)
	 *
	 * We want to merge (1) and (2) to obtain the desired data. 
	 * (3), (4), and (5) are only the server's responses and are
	 * not involved in aggregation; they are not the data we need.
	 */
	if (handshake.content_type == 0x16 &&
	    (handshake.handshake_type == 0xb ||
	     handshake.handshake_type == 0xc ||
	     handshake.handshake_type == 0xe))
		return MSG_UNKNOWN;

	/*
	 * For the client program, it ends with 'Protocol: Change Cipher Spec'.
	 * If all data collection has been completed, we set the flag bit.
	 */
	if (handshake.content_type == 0x14
	    && is_socket_info_valid(conn_info->socket_info_ptr)) {
		conn_info->socket_info_ptr->tls_end = 1;
	}

	/*
	 * 0x01: handshake type=Client Hello
	 * 0x10: handshake type=client key exchange
	 */
	if (handshake.handshake_type == 0x1 || handshake.handshake_type == 0x10)
		return MSG_REQUEST;
	else
		return MSG_RESPONSE;
}

static __inline int is_http_response(const char *data)
{
	return (data[0] == 'H' && data[1] == 'T' && data[2] == 'T'
		&& data[3] == 'P' && data[4] == '/' && data[5] == '1'
		&& data[6] == '.' && data[8] == ' ');
}

static __inline int is_http_request(const char *data, int data_len)
{
	switch (data[0]) {
		/* DELETE */
	case 'D':
		if ((data[1] != 'E') || (data[2] != 'L') || (data[3] != 'E')
		    || (data[4] != 'T') || (data[5] != 'E')
		    || (data[6] != ' ')) {
			return 0;
		}
		break;

		/* GET */
	case 'G':
		if ((data[1] != 'E') || (data[2] != 'T') || (data[3] != ' ')) {
			return 0;
		}
		break;

		/* HEAD */
	case 'H':
		if ((data[1] != 'E') || (data[2] != 'A') || (data[3] != 'D')
		    || (data[4] != ' ')) {
			return 0;
		}
		break;

		/* OPTIONS */
	case 'O':
		if (data_len < 8 || (data[1] != 'P') || (data[2] != 'T')
		    || (data[3] != 'I') || (data[4] != 'O') || (data[5] != 'N')
		    || (data[6] != 'S') || (data[7] != ' ')) {
			return 0;
		}
		break;

		/* PATCH/POST/PUT */
	case 'P':
		switch (data[1]) {
		case 'A':
			if ((data[2] != 'T') || (data[3] != 'C')
			    || (data[4] != 'H') || (data[5] != ' ')) {
				return 0;
			}
			break;
		case 'O':
			if ((data[2] != 'S') || (data[3] != 'T')
			    || (data[4] != ' ')) {
				return 0;
			}
			break;
		case 'U':
			if ((data[2] != 'T') || (data[3] != ' ')) {
				return 0;
			}
			break;
		default:
			return 0;
		}
		break;

	default:
		return 0;
	}

	return 1;
}

static __inline enum message_type infer_http_message(const char *buf,
						     size_t count,
						     struct conn_info_s
						     *conn_info)
{
	// HTTP/1.1 200 OK\r\n (HTTP response is 17 characters)
	// GET x HTTP/1.1\r\n (HTTP response is 16 characters)
	// MAY be without "OK", ref:https://www.rfc-editor.org/rfc/rfc7231
	if (count < 14) {
		return MSG_UNKNOWN;
	}

	if (!protocol_port_check(PROTO_HTTP1, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP1)
			return MSG_UNKNOWN;
	}

	if (is_http_response(buf)) {
		return MSG_RESPONSE;
	}

	if (is_http_request(buf, count)) {
		return MSG_REQUEST;
	}

	return MSG_UNKNOWN;
}


/*
0                   15 16                     31
|---------------------|-----------------------|
|    标识 ID          |     标志 flags        |
|---------------------|-----------------------|
|    问题数           |    资源记录数         |
|---------------------|-----------------------|
|    授权资源记录数   |    附加资源记录数     |
|---------------------|-----------------------|
*/
struct dns_header {
	unsigned short id;	// identification number

	unsigned char rd:1;	// recursion desired
	unsigned char tc:1;	// truncated message
	unsigned char aa:1;	// authoritive answer
	unsigned char opcode:4;	// purpose of message
	unsigned char qr:1;	// query/response flag

	unsigned char rcode:4;	// response code
	unsigned char cd:1;	// checking disabled
	unsigned char ad:1;	// authenticated data
	unsigned char z:1;	// its z! reserved
	unsigned char ra:1;	// recursion available

	unsigned short q_count;	// number of question entries
	unsigned short ans_count;	// number of answer entries
	unsigned short auth_count;	// number of authority entries
	unsigned short add_count;	// number of resource entries
};

static __inline enum message_type infer_dns_message(const char *buf,
						    size_t count,
						    const char *ptr,
						    __u32 infer_len,
						    struct conn_info_s
						    *conn_info)
{
	/*
	 * Note: When testing with 'curl' accessing a domain, the following
	 * situations are observed in DNS:
	 * (1) An 'A' type DNS request is sent.
	 * (2) An 'A' type response is received.
	 * (3) An 'AAAA' type response is received.
	 *
	 * It is noticed that the Transaction ID for (2) and (3) are different.
	 * We observe that the data obtained through eBPF is missing the data for
	 * the 'AAAA' type request, which differs from the data obtained through
	 * the ‘AF_PACKET’ method ('AF_PACKET' method includes data for the 'AAAA'
	 * type request).
	 */

	const int dns_header_size = 12;

	// This is the typical maximum size for DNS.
	const int dns_msg_max_size = 512;

	// Maximum number of resource records.
	// https://stackoverflow.com/questions/6794926/how-many-a-records-can-fit-in-a-single-dns-response
	const int max_num_rr = 25;

	if (count < dns_header_size || count > dns_msg_max_size) {
		return MSG_UNKNOWN;
	}

	if (!protocol_port_check(PROTO_DNS, conn_info))
		return MSG_UNKNOWN;

	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_DNS)
			return MSG_UNKNOWN;
	}

	bool update_tcp_dns_prev_count = false;
	struct dns_header *dns = (struct dns_header *)buf;
	if (conn_info->tuple.l4_protocol == IPPROTO_TCP) {
		if (__bpf_ntohs(dns->id) + 2 == count) {
			dns = (struct dns_header*) dns + 2;
		} else {
			update_tcp_dns_prev_count = true;
		}
	}

	__u16 num_questions = __bpf_ntohs(dns->q_count);
	__u16 num_answers = __bpf_ntohs(dns->ans_count);
	__u16 num_auth = __bpf_ntohs(dns->auth_count);
	__u16 num_addl = __bpf_ntohs(dns->add_count);

	bool qr = dns->qr;	// QR（Response）：查询请求/响应的标志信息。查询请求时，值为 0；响应时，值为 1。
	__u8 opcode = dns->opcode;	// 操作码。其中，0 表示标准查询；1 表示反向查询；2 表示服务器状态请求。
	__u8 zero = dns->z;	// Z：保留字段，在所有的请求和应答报文中，它的值必须为 0。
	if (zero != 0) {
		return MSG_UNKNOWN;
	}

	if (opcode != 0) {	//非标准查询不予处理
		return MSG_UNKNOWN;
	}

	if (num_questions == 0 || num_questions > 10) {
		return MSG_UNKNOWN;
	}

	__u32 num_rr = num_questions + num_answers + num_auth + num_addl;
	if (num_rr > max_num_rr) {
		return MSG_UNKNOWN;
	}
	// FIXME: Remove this code when the call chain can correctly handle the
	// Go DNS case.
	/*
	 * Here, we assume a maximum length of 128 bytes for the queries name.
	 * If queries name exceeds 128 bytes, the identification of AAAA or A
	 * types will be impossible.
	 *
	 * For decreasing the stack usage, we use a 32-byte buffer to store the
	 * queries name, and repeatedly read the queries name from the buffer.
	 */
	conn_info->dns_q_type = 0;
	__u8 tmp_buf[32];
	const char *queries_start = ptr + (((char *)(dns + 1)) - buf);
	for (int i = 0; i < 4; i++) {
		short tmp = bpf_probe_read_user_str(tmp_buf, sizeof(tmp_buf),
						    queries_start);
		if (tmp < 0) {
			break;
		}
		if (tmp != sizeof(tmp_buf)) {
			queries_start += tmp;
			bpf_probe_read_user(tmp_buf, 2, queries_start);
			conn_info->dns_q_type = __bpf_ntohs(*(__u16 *) tmp_buf);
			break;
		} else {
			queries_start += tmp - 1;
		}
	}
	// coreDNS will first send the length in two bytes. If it recognizes
	// that it is TCP DNS and does not have a length field, it will modify
	// the offset to correct the TCP sequence number.
	if (update_tcp_dns_prev_count) {
		conn_info->prev_count = 2;
	}
	return (qr == 0) ? MSG_REQUEST : MSG_RESPONSE;
}

static bool is_http2_magic(const char *buf_src, size_t count)
{
	static const char magic[] = "PRI * HTTP/2";
	char buffer[sizeof(magic)] = { 0 };
	bpf_probe_read_user(buffer, sizeof(buffer) - 1, buf_src);
	for (int idx = 0; idx < sizeof(magic); ++idx) {
		if (magic[idx] == buffer[idx])
			continue;
		return false;
	}
	return true;
}

static __inline __u8 get_block_fragment_offset(__u8 fix_sz,
					       __u8 flags_padding,
					       __u8 flags_priority)
{
	__u8 offset = 0;
	offset = fix_sz;

	if (flags_padding)
		offset += 1;
	if (flags_priority)
		offset += 5;

	return offset;
}
#define try_find__static_table_idx() \
do { \
	if (table_idx > max || table_idx == 0) \
		table_idx = buf[++offset] & 0x7f; \
} while(0)
static __inline __u8 find_idx_from_block_fragment(const __u8 * buf,
						  __u8 offset, __u8 max)
{
	/*
	 * Header Block Fragment解析出静态表索引值，最多取前面6个字节。
	 * 例如：Header Block Fragment: ddda8386e6e5e4e3e2d0 最多分析'dd da 83 86 e6 e5'
	 */
	__u8 table_idx = buf[offset] & 0x7f;
	try_find__static_table_idx();
	try_find__static_table_idx();
	try_find__static_table_idx();
	try_find__static_table_idx();
	try_find__static_table_idx();

	return table_idx;
}

static __inline enum message_type parse_http2_headers_frame(const char
							    *buf_kern,
							    size_t syscall_len,
							    const char *buf_src,
							    size_t count,
							    struct conn_info_s
							    *conn_info,
							    const bool is_first)
{
#define HTTPV2_FRAME_PROTO_SZ           0x9
#define HTTPV2_FRAME_TYPE_HEADERS       0x1
#define HTTPV2_STATIC_TABLE_AUTH_IDX    0x1
#define HTTPV2_STATIC_TABLE_GET_IDX     0x2
#define HTTPV2_STATIC_TABLE_POST_IDX    0x3
#define HTTPV2_STATIC_TABLE_PATH_1_IDX  0x4
#define HTTPV2_STATIC_TABLE_PATH_2_IDX  0x5
// In some cases, the compiled binary instructions exceed the limit, the
// specific reason is unknown, reduce the number of cycles of http2, which
// may cause http2 packet loss
#ifdef LINUX_VER_5_2_PLUS
#define HTTPV2_LOOP_MAX 8
#else
#define HTTPV2_LOOP_MAX 7
#endif
/*
 *  HTTPV2_FRAME_READ_SZ取值考虑以下3部分：
 *  (1) fixed 9-octet header
 *
 *  HEADERS 帧:
 *  (2) Pad Length (8) + E(1) + Stream Dependency(31) + Weight(8) = 6 bytes
 *  (3) Header Block Fragment (*) 取 6bytes
 */
#define HTTPV2_FRAME_READ_SZ            21
#define HTTPV2_STATIC_TABLE_IDX_MAX     61

	/*
	 * If the server reads data in multiple passes, and the previous pass
	 * has already read the first 9 bytes of the protocol header, and it
	 * has been determined as HEADER, then the current data is directly
	 * PUSHed to the upper layer.
	 */
	if (conn_info->prev_count == HTTPV2_FRAME_PROTO_SZ) {
		return MSG_REQUEST;
	}
	// fixed 9-octet header
	if (count < HTTPV2_FRAME_PROTO_SZ)
		return MSG_UNKNOWN;

	__u32 offset = 0;
	__u8 flags_unset = 0, flags_padding = 0, flags_priority = 0;
	__u8 type = 0, reserve = 0, static_table_idx, i, block_fragment_offset;
	__u8 msg_type = MSG_UNKNOWN;
	__u8 buf[HTTPV2_FRAME_READ_SZ] = { 0 };

	// When Magic and header are in the same TCP packet, it will cause
	// packet loss. When Magic is detected, the offset is corrected to the
	// starting position of the header.
	if (is_first && is_http2_magic(buf_src, count)) {
		static const int HTTP2_MAGIC_SIZE = 24;
		offset = HTTP2_MAGIC_SIZE;
	}

	/*
	 * Use '#pragma unroll' to avoid the following error during the
	 * loading process in Linux 5.2.x:
	 * bpf load "socket-trace-bpf-linux-5.2_plus" failed, error:Invalid argument (22)
	 */
#pragma unroll
	for (i = 0; i < HTTPV2_LOOP_MAX; i++) {

		/*
		 * 这个地方考虑iovecs的情况，传递过来进行协议推断的数据
		 * 是&args->iov[0]第一个iovec，count的值也是第一个
		 * iovec的数据长度。存在协议分析出来长度是大于count的情况
		 * 因此这里不能通过“offset == count”来进行判断。
		 */
		if (offset >= count)
			break;

		conn_info->tcpseq_offset = offset;
		bpf_probe_read_user(buf, sizeof(buf), buf_src + offset);
		offset += (__bpf_ntohl(*(__u32 *) buf) >> 8) +
		    HTTPV2_FRAME_PROTO_SZ;
		type = buf[3];

		// 如果不是Header继续寻找下一个Frame
		if (type != HTTPV2_FRAME_TYPE_HEADERS)
			continue;

		flags_unset = buf[4] & 0xd2;
		flags_padding = buf[4] & 0x08;
		flags_priority = buf[4] & 0x20;
		reserve = buf[5] & 0x01;

		// flags_unset和reserve必须为0，否则直接放弃判断。
		if (flags_unset || reserve)
			return MSG_UNKNOWN;

		if (syscall_len == HTTPV2_FRAME_PROTO_SZ) {
			msg_type = MSG_PRESTORE;
			break;
		}

		/*
		 * If the protocol inference is complete, it can be directly
		 * pushed to the upper layer.
		 */
		if (!is_first)
			return MSG_REQUEST;

		/*
		 * 根据帧结构中的flags的不同设置(具体检查PADDING位和PRIORITY位)
		 * 来确定HEADERS帧的内容从而得到Header Block Fragment的偏移。
		 */
		block_fragment_offset =
		    get_block_fragment_offset(HTTPV2_FRAME_PROTO_SZ,
					      flags_padding, flags_priority);

		// 对Header Block Fragment的内容进行分析得到静态表的索引。
		static_table_idx =
		    find_idx_from_block_fragment(buf, block_fragment_offset,
						 HTTPV2_STATIC_TABLE_IDX_MAX);

		// 静态索引表的Index取值范围 [1, 61]
		if (static_table_idx > HTTPV2_STATIC_TABLE_IDX_MAX &&
		    static_table_idx == 0)
			continue;

		// HTTPV2 REQUEST
		if (static_table_idx == HTTPV2_STATIC_TABLE_AUTH_IDX ||
		    static_table_idx == HTTPV2_STATIC_TABLE_GET_IDX ||
		    static_table_idx == HTTPV2_STATIC_TABLE_POST_IDX ||
		    static_table_idx == HTTPV2_STATIC_TABLE_PATH_1_IDX ||
		    static_table_idx == HTTPV2_STATIC_TABLE_PATH_2_IDX) {
			msg_type = MSG_REQUEST;

		} else {

			/*
			 * If the data type of HTTPV2 is RESPONSE in the initial
			 * judgment, then the inference will be discarded directly.
			 * Because the data obtained for the first time is RESPONSE,
			 * it can be considered as invalid data (the REQUEST cannot
			 * be found for aggregation, and the judgment of RESPONSE is
			 * relatively rough and prone to misjudgment).
			 */
			if (is_first)
				return MSG_UNKNOWN;

			msg_type = MSG_RESPONSE;
		}

		break;
	}

	if (msg_type == MSG_PRESTORE)
		save_prev_data_from_kern(buf_kern, conn_info,
					 HTTPV2_FRAME_PROTO_SZ);

	return msg_type;
}



static __inline enum message_type infer_http2_message(const char *buf_kern,
						      size_t syscall_len,
						      const char *buf_src,
						      size_t count,
						      struct conn_info_s
						      *conn_info)
{
	if (!protocol_port_check(PROTO_HTTP2, conn_info))
		return MSG_UNKNOWN;

	// When go uprobe http2 cannot be used, use kprobe/tracepoint to collect data
	// if (skip_http2_kprobe()) {
	// 	if (conn_info->direction == T_INGRESS &&
	// 	    conn_info->tuple.l4_protocol == IPPROTO_TCP) {
	// 		struct http2_tcp_seq_key tcp_seq_key = {
	// 			.tgid = bpf_get_current_pid_tgid() >> 32,
	// 			.fd = conn_info->fd,
	// 			.tcp_seq_end =
	// 			    get_tcp_read_seq_from_fd(conn_info->fd),
	// 		};
	// 		// make linux 4.14 validator happy
	// 		__u32 tcp_seq = tcp_seq_key.tcp_seq_end - count;
	// 		bpf_map_update_elem(&http2_tcp_seq_map, &tcp_seq_key,
	// 				    &tcp_seq, BPF_NOEXIST);
	// 	}
	// 	return MSG_UNKNOWN;
	// }

	bool is_first = true;	// Is it the first inference?
	if (is_infer_socket_valid(conn_info->socket_info_ptr)) {
		if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP2)
			return MSG_UNKNOWN;
		is_first = false;
	}

	enum message_type ret =
	    parse_http2_headers_frame(buf_kern, syscall_len, buf_src, count,
				      conn_info, is_first);

	return ret;
}



static __inline struct protocol_message_t
infer_protocol(struct ctx_info_s *ctx,
			   const struct data_args_t *args,
			   size_t count,
			   struct conn_info_s *conn_info,
			   __u8 sk_state, 
			   const struct process_data_extra *extra)
{
	struct protocol_message_t inferred_message;
	inferred_message.protocol = PROTO_UNKNOWN;
	inferred_message.type = MSG_UNKNOWN;

	if (conn_info->sk == NULL)
		return inferred_message;

	if (conn_info->tuple.dport == 0 || conn_info->tuple.num == 0)
	{
		return inferred_message;
	}

	/*
	 * The socket that is indeed determined to be a protocol does not
	 * enter drop_msg_by_comm().
	 */
	if (!is_socket_info_valid(conn_info->socket_info_ptr))
	{
		if (drop_msg_by_comm())
			return inferred_message;
	}

	const char *buf = args->buf;
	struct infer_data_s *__infer_buf = &ctx->infer_buf;

	/*
	 * Some protocols are difficult to infer from the first 32 bytes
	 * of data and require more data to be involved in the inference
	 * process.
	 *
	 * In such cases, we can directly pass the buffer address of the
	 * system call for inference.
	 * Examples of such protocols include HTTP2 and Postgre.
	 *
	 * infer_buf:
	 *     The prepared 32-byte inference data has been placed in the buffer.
	 * syscall_infer_addr:
	 *     Just a buffer address needs to call the bpf_probe_read_user() interface
	 *     to read data. Special note is that if extra->vecs is true,
	 *     its value is the address of the first iov, and syscall_infer_len is
	 *     the length of the first iov.
	 */
	char *syscall_infer_addr = (char*)NULL;
	__u32 syscall_infer_len = 0;
	if (extra->vecs)
	{
		__infer_buf->len = infer_iovecs_copy(__infer_buf, args,
											 count, DATA_BUF_MAX,
											 &syscall_infer_addr,
											 &syscall_infer_len);
		/*
		 * The syscall_infer_len(iov_cpy.iov_len) may be larger than
		 * syscall length, make adjustments here.
		 */
		if (syscall_infer_len > count)
			syscall_infer_len = count;
	}
	else
	{
		bpf_probe_read_user(__infer_buf->data,
							sizeof(__infer_buf->data), buf);
		syscall_infer_addr = (char *)buf;
		syscall_infer_len = count;
	}

	char *infer_buf = __infer_buf->data;
	conn_info->count = count;
	conn_info->syscall_infer_addr = syscall_infer_addr;
	conn_info->syscall_infer_len = syscall_infer_len;

	check_and_fetch_prev_data(conn_info);

	// In the initial stage of data protocol inference, reassembly check.
	check_and_set_data_reassembly(conn_info);

	/*
	 * TLS protocol datas cause other L7 protocols inference misjudgment,
	 * sometimes HTTPS protocol datas is incorrectly inferred as MQTT, DUBBO protocol.
	 * TLS protocol is difficult to identify with features, the port filtering for
	 * the TLS protocol is performed here.
	 */

	/*
	 * If the current port number is configured for the TLS protocol.
	 * If the data source comes from kernel system calls, it is discarded
	 * directly because some kernel probes do not handle TLS data.
	 */
	if (protocol_port_check(PROTO_TLS, conn_info) &&
		extra->source == DATA_SOURCE_SYSCALL)
	{
		/*
		 * TLS first performs handshake protocol inference and discards the data
		 * directly if it is unsuccessful.
		 */
		if ((inferred_message.type =
				 infer_tls_message(infer_buf, count,
								   conn_info)) != MSG_UNKNOWN)
		{
			inferred_message.protocol = PROTO_TLS;
			return inferred_message;
		}
		else
		{
			return inferred_message;
		}
	}

	/*
	 * Note:
	 * Use the 'protocol_port_check_1()' interface when performing specific protocol
	 * inference checks.
	 */

	/*
	 * Protocol inference fast matching.
	 * One thread or process processes the application layer data, and the protocol
	 * inference program has successfully concluded that the protocol is A, then
	 * this thread or process will probably process the data of protocol A later.
	 * We can add a cache for fast matching, use the process-ID/thread-ID
	 * to query the protocol recorded in the cache, and match the protocol preferentially.
	 * If the match fails, a slow match is performed (all protocol sequence matches).
	 *
	 * Due to the limitation of the number of eBPF instruction in kernel, this feature
	 * is suitable for Linux5.2+
	 */

	__u32 pid = bpf_get_current_pid_tgid()>>32;
	__u32 cache_key = pid >> 32;
	__u8 skip_proto = PROTO_UNKNOWN;
	if (cache_key < PROTO_INFER_CACHE_SIZE)
	{
		struct proto_infer_cache_t *p;
		p = proto_infer_cache_map__lookup(&cache_key);
		if (p == NULL)
			return inferred_message;
		// https://stackoverflow.com/questions/70750259/bpf-verification-error-when-trying-to-extract-sni-from-tls-packet
		__u8 this_proto = p->protocols[(__u16)pid];
		switch (this_proto)
		{
		case PROTO_HTTP1:
			if ((inferred_message.type =
					 infer_http_message(infer_buf, count,
										conn_info)) != MSG_UNKNOWN)
			{
				inferred_message.protocol = PROTO_HTTP1;
				return inferred_message;
			}
			break;
		case PROTO_DNS:
			if ((inferred_message.type =
					 infer_dns_message(infer_buf, count,
									   syscall_infer_addr,
									   syscall_infer_len,
									   conn_info)) != MSG_UNKNOWN)
			{
				inferred_message.protocol = PROTO_DNS;
				return inferred_message;
			}
			break;
		case PROTO_HTTP2:
			if ((inferred_message.type =
					 infer_http2_message(infer_buf, count,
										 syscall_infer_addr,
										 syscall_infer_len,
										 conn_info)) != MSG_UNKNOWN)
			{
				inferred_message.protocol = PROTO_HTTP2;
				return inferred_message;
			}
			break;
		}
	}
		// for other L7 Protol, now pass them which will be implemented in the future
		//
		// case PROTO_REDIS:
		// 	if ((inferred_message.type =
		// 			 infer_redis_message(infer_buf, count,
		// 								 conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_REDIS;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_MQTT:
		// 	if ((inferred_message.type =
		// 			 infer_mqtt_message(infer_buf, count,
		// 								conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_MQTT;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_AMQP:
		// 	if ((inferred_message.type =
		// 			 infer_amqp_message(infer_buf, count,
		// 								conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_AMQP;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_NATS:
		// 	if ((inferred_message.type =
		// 			 infer_nats_message(infer_buf, count,
		// 								syscall_infer_addr,
		// 								syscall_infer_len,
		// 								conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_NATS;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_PULSAR:
		// 	if ((inferred_message.type =
		// 			 infer_pulsar_message(syscall_infer_addr,
		// 								  syscall_infer_len,
		// 								  count,
		// 								  conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_PULSAR;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_DUBBO:
		// 	if ((inferred_message.type =
		// 			 infer_dubbo_message(infer_buf, count,
		// 								 conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_DUBBO;
		// 		return inferred_message;
		// 	}
		// 	break;

		// case PROTO_MYSQL:
		// 	if ((inferred_message.type =
		// 			 infer_mysql_message(infer_buf, count,
		// 								 conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		if (inferred_message.type == MSG_PRESTORE)
		// 			return inferred_message;
		// 		inferred_message.protocol = PROTO_MYSQL;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_KAFKA:
		// 	if ((inferred_message.type =
		// 			 infer_kafka_message(infer_buf, count,
		// 								 conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		if (inferred_message.type == MSG_PRESTORE)
		// 			return inferred_message;
		// 		inferred_message.protocol = PROTO_KAFKA;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_SOFARPC:
		// 	if ((inferred_message.type =
		// 			 infer_sofarpc_message(infer_buf, count,
		// 								   conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_SOFARPC;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_FASTCGI:
		// 	if ((inferred_message.type =
		// 			 infer_fastcgi_message(infer_buf, count,
		// 								   conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		if (inferred_message.type == MSG_PRESTORE)
		// 			return inferred_message;
		// 		inferred_message.protocol = PROTO_FASTCGI;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_BRPC:
		// 	if ((inferred_message.type =
		// 			 infer_brpc_message(infer_buf, count,
		// 								conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_BRPC;
		// 		return inferred_message;
		// 	}
		// 	break;

		// case PROTO_POSTGRESQL:
		// 	if ((inferred_message.type =
		// 			 infer_postgre_message(syscall_infer_addr,
		// 								   syscall_infer_len,
		// 								   conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_POSTGRESQL;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_ORACLE:
		// 	if ((inferred_message.type =
		// 			 infer_oracle_tns_message(infer_buf, count,
		// 									  conn_info)) !=
		// 		MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_ORACLE;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_MONGO:
		// 	if ((inferred_message.type =
		// 			 infer_mongo_message(infer_buf, count,
		// 								 conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_MONGO;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_OPENWIRE:
		// 	if ((inferred_message.type =
		// 			 infer_openwire_message(infer_buf, count,
		// 									conn_info)) !=
		// 		MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_OPENWIRE;
		// 		return inferred_message;
		// 	}
		// 	break;
		// case PROTO_ZMTP:
		// 	if ((inferred_message.type =
		// 			 infer_zmtp_message(infer_buf, count,
		// 								syscall_infer_addr,
		// 								syscall_infer_len,
		// 								conn_info)) != MSG_UNKNOWN)
		// 	{
		// 		inferred_message.protocol = PROTO_ZMTP;
		// 		return inferred_message;
		// 	}
		// 	break;
	// 	default:
	// 		break;
	// 	}

	// 	/*
	// 	 * Going here means that no hit is going to be counted in the
	// 	 * slow path. We want the slow path to skip this protocol inference
	// 	 * to avoid duplicate matches.
	// 	 */
	// 	skip_proto = this_proto;
	// 	conn_info->skip_proto = this_proto;
	// }

	/*
	 * Enter the slow matching path.
	 */

	/*
	 * 为了提高协议推断的准确率，做了一下处理：
	 *
	 * 数据一旦首次被推断成功，就会把推断的L7协议类型设置到socket上，这样
	 * 凡是通过此socket读写的所有数据，协议类型就已经被确定了。
	 * 协议推断程序可以快速判断是否要进行数据推断处理。
	 * 例如：
	 *   在 infer_http_message() 中可以快速通过
	 *      if (conn_info->socket_info_ptr->l7_proto != PROTO_HTTP1)
	 *              return MSG_UNKNOWN;
	 *     ... ...
	 *   进行快速判断。
	 */

	if (skip_proto != PROTO_HTTP1 && (inferred_message.type =
										  infer_http_message(infer_buf, count, conn_info)) != MSG_UNKNOWN)
	{
		inferred_message.protocol = PROTO_HTTP1;
	}
	else if (skip_proto != PROTO_DNS && (inferred_message.type =
											 infer_dns_message(infer_buf, count,
															   syscall_infer_addr,
															   syscall_infer_len,
															   conn_info)) != MSG_UNKNOWN)
	{
		inferred_message.protocol = PROTO_DNS;
	}

	if (inferred_message.protocol != MSG_UNKNOWN){
		return inferred_message;

	}
	else if (skip_proto != PROTO_HTTP2 && (inferred_message.type =
											   infer_http2_message(infer_buf, count, syscall_infer_addr,
																   syscall_infer_len,
																   conn_info)) != MSG_UNKNOWN)
	{
		inferred_message.protocol = PROTO_HTTP2;
	}

	return inferred_message;
}










#endif