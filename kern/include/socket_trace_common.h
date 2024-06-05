#include <vmlinux.h>
#include "common.h"
struct socket_info_s {
	__u16 l7_proto;

	/*
	 * Indicate whether this socket is allowed for reassembly,
	 * determined by the configuration of protocol reassembly.
	 */
	__u16 allow_reassembly: 1;
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