#include "common.h"
#include "socket_trace.h"


static __inline struct protocol_message_t
infer_protocol(struct ctx_info_s *ctx,
		 const struct data_args_t *args,
		 size_t count,
		 struct conn_info_s *conn_info,
		 __u8 sk_state, const struct process_data_extra *extra)
{
	struct protocol_message_t inferred_message;
	inferred_message.protocol = PROTO_UNKNOWN;
	inferred_message.type = MSG_UNKNOWN;

	if (conn_info->sk == NULL)
		return inferred_message;

	if (conn_info->tuple.dport == 0 || conn_info->tuple.num == 0) {
		return inferred_message;
	}

	/*
	 * The socket that is indeed determined to be a protocol does not
	 * enter drop_msg_by_comm().
	 */
	if (!is_socket_info_valid(conn_info->socket_info_ptr)) {
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
	char *syscall_infer_addr = NULL;
	__u32 syscall_infer_len = 0;
	if (extra->vecs) {
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
	} else {
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
	if (protocol_port_check_1(PROTO_TLS, conn_info) &&
	    extra->source == DATA_SOURCE_SYSCALL) {
		/*
		 * TLS first performs handshake protocol inference and discards the data
		 * directly if it is unsuccessful.
		 */
		if ((inferred_message.type =
		     infer_tls_message(infer_buf, count,
				       conn_info)) != MSG_UNKNOWN) {
			inferred_message.protocol = PROTO_TLS;
			return inferred_message;
		} else {
			return inferred_message;
		}
	}

	/*
	 * Note:
	 * Use the 'protocol_port_check_1()' interface when performing specific protocol
	 * inference checks.
	 */
#ifdef LINUX_VER_5_2_PLUS
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

	__u32 pid = (__u32) bpf_get_current_pid_tgid();
	__u32 cache_key = pid >> 16;
	__u8 skip_proto = PROTO_UNKNOWN;
	if (cache_key < PROTO_INFER_CACHE_SIZE) {
		struct proto_infer_cache_t *p;
		p = proto_infer_cache_map__lookup(&cache_key);
		if (p == NULL)
			return inferred_message;
		// https://stackoverflow.com/questions/70750259/bpf-verification-error-when-trying-to-extract-sni-from-tls-packet
		__u8 this_proto = p->protocols[(__u16) pid];
		switch (this_proto) {
		case PROTO_HTTP1:
			if ((inferred_message.type =
			     infer_http_message(infer_buf, count,
						conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_HTTP1;
				return inferred_message;
			}
			break;
		case PROTO_REDIS:
			if ((inferred_message.type =
			     infer_redis_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_REDIS;
				return inferred_message;
			}
			break;
		case PROTO_MQTT:
			if ((inferred_message.type =
			     infer_mqtt_message(infer_buf, count,
						conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_MQTT;
				return inferred_message;
			}
			break;
		case PROTO_AMQP:
			if ((inferred_message.type =
			     infer_amqp_message(infer_buf, count,
						conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_AMQP;
				return inferred_message;
			}
			break;
		case PROTO_NATS:
			if ((inferred_message.type =
			     infer_nats_message(infer_buf, count,
						syscall_infer_addr,
						syscall_infer_len,
						conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_NATS;
				return inferred_message;
			}
			break;
		case PROTO_PULSAR:
			if ((inferred_message.type =
			     infer_pulsar_message(syscall_infer_addr,
						  syscall_infer_len,
						  count,
						  conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_PULSAR;
				return inferred_message;
			}
			break;
		case PROTO_DUBBO:
			if ((inferred_message.type =
			     infer_dubbo_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_DUBBO;
				return inferred_message;
			}
			break;
		case PROTO_DNS:
			if ((inferred_message.type =
			     infer_dns_message(infer_buf, count,
					       syscall_infer_addr,
					       syscall_infer_len,
					       conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_DNS;
				return inferred_message;
			}
			break;
		case PROTO_MYSQL:
			if ((inferred_message.type =
			     infer_mysql_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				if (inferred_message.type == MSG_PRESTORE)
					return inferred_message;
				inferred_message.protocol = PROTO_MYSQL;
				return inferred_message;
			}
			break;
		case PROTO_KAFKA:
			if ((inferred_message.type =
			     infer_kafka_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				if (inferred_message.type == MSG_PRESTORE)
					return inferred_message;
				inferred_message.protocol = PROTO_KAFKA;
				return inferred_message;
			}
			break;
		case PROTO_SOFARPC:
			if ((inferred_message.type =
			     infer_sofarpc_message(infer_buf, count,
						   conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_SOFARPC;
				return inferred_message;
			}
			break;
		case PROTO_FASTCGI:
			if ((inferred_message.type =
			     infer_fastcgi_message(infer_buf, count,
						   conn_info)) != MSG_UNKNOWN) {
				if (inferred_message.type == MSG_PRESTORE)
					return inferred_message;
				inferred_message.protocol = PROTO_FASTCGI;
				return inferred_message;
			}
			break;
		case PROTO_BRPC:
			if ((inferred_message.type =
			     infer_brpc_message(infer_buf, count,
						conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_BRPC;
				return inferred_message;
			}
			break;
		case PROTO_HTTP2:
			if ((inferred_message.type =
			     infer_http2_message(infer_buf, count,
						 syscall_infer_addr,
						 syscall_infer_len,
						 conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_HTTP2;
				return inferred_message;
			}
			break;
		case PROTO_POSTGRESQL:
			if ((inferred_message.type =
			     infer_postgre_message(syscall_infer_addr,
						   syscall_infer_len,
						   conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_POSTGRESQL;
				return inferred_message;
			}
			break;
		case PROTO_ORACLE:
			if ((inferred_message.type =
			     infer_oracle_tns_message(infer_buf, count,
						      conn_info)) !=
			    MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_ORACLE;
				return inferred_message;
			}
			break;
		case PROTO_MONGO:
			if ((inferred_message.type =
			     infer_mongo_message(infer_buf, count,
						 conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_MONGO;
				return inferred_message;
			}
			break;
		case PROTO_OPENWIRE:
			if ((inferred_message.type =
			     infer_openwire_message(infer_buf, count,
						    conn_info)) !=
			    MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_OPENWIRE;
				return inferred_message;
			}
			break;
		case PROTO_ZMTP:
			if ((inferred_message.type =
			     infer_zmtp_message(infer_buf, count,
						syscall_infer_addr,
						syscall_infer_len,
						conn_info)) != MSG_UNKNOWN) {
				inferred_message.protocol = PROTO_ZMTP;
				return inferred_message;
			}
			break;
		default:
			break;
		}

		/*
		 * Going here means that no hit is going to be counted in the
		 * slow path. We want the slow path to skip this protocol inference
		 * to avoid duplicate matches.
		 */
		skip_proto = this_proto;
		conn_info->skip_proto = this_proto;
	}

	/*
	 * Enter the slow matching path.
	 */
#endif

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
#ifdef LINUX_VER_5_2_PLUS
	if (skip_proto != PROTO_HTTP1 && (inferred_message.type =
#else
	if ((inferred_message.type =
#endif
	     infer_http_message(infer_buf, count, conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_HTTP1;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_REDIS && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_redis_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_REDIS;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_MQTT && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_mqtt_message(infer_buf, count,
				       conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_MQTT;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_DNS && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_dns_message(infer_buf, count,
				      syscall_infer_addr,
				      syscall_infer_len,
				      conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_DNS;
	}

	if (inferred_message.protocol != MSG_UNKNOWN)
		return inferred_message;

#ifdef LINUX_VER_5_2_PLUS
	if (skip_proto != PROTO_MYSQL && (inferred_message.type =
#else
	if ((inferred_message.type =
#endif
	     infer_mysql_message(infer_buf, count, conn_info)) != MSG_UNKNOWN) {
		if (inferred_message.type == MSG_PRESTORE)
			return inferred_message;
		inferred_message.protocol = PROTO_MYSQL;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_KAFKA && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_kafka_message(infer_buf, count,
					conn_info)) != MSG_UNKNOWN) {
		if (inferred_message.type == MSG_PRESTORE)
			return inferred_message;
		inferred_message.protocol = PROTO_KAFKA;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_SOFARPC && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_sofarpc_message(infer_buf, count,
					  conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_SOFARPC;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_FASTCGI && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_fastcgi_message(infer_buf, count,
					  conn_info)) != MSG_UNKNOWN) {
		if (inferred_message.type == MSG_PRESTORE)
			return inferred_message;
		inferred_message.protocol = PROTO_FASTCGI;
#ifdef LINUX_VER_5_2_PLUS
	} else if (skip_proto != PROTO_HTTP2 && (inferred_message.type =
#else
	} else if ((inferred_message.type =
#endif
		    infer_http2_message(infer_buf, count, syscall_infer_addr,
					syscall_infer_len,
					conn_info)) != MSG_UNKNOWN) {
		inferred_message.protocol = PROTO_HTTP2;
	}

	return inferred_message;
}