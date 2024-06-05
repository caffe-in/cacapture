#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "socket_trace.h"
static __inline void *get_socket_file_addr_with_check(struct task_struct *task,
						      int fd_num,
						      int files_off,
						      int fdt_off)
{
	void *file = NULL;
	void *files, *files_ptr = (void *)task + files_off;
	bpf_probe_read_kernel(&files, sizeof(files), files_ptr);

	if (files == NULL)
		return NULL;

	struct fdtable *fdt, __fdt;

	bpf_probe_read_kernel(&fdt, sizeof(fdt), files + fdt_off);
	bpf_probe_read_kernel(&__fdt, sizeof(__fdt), (void *)fdt);

	if (fd_num >= (int)__fdt.max_fds)
		return NULL;

	bpf_probe_read_kernel(&file, sizeof(file), __fdt.fd + fd_num);

	return file;
}
static __inline void *get_socket_from_fd(int fd_num,
					 struct member_fields_offset *offset)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	void *file = NULL;
	file =
	    get_socket_file_addr_with_check(task, fd_num,
					    offset->task__files_offset,
					    offset->
					    struct_files_struct_fdt_offset);
	if (file == NULL)
		return NULL;
	void *private_data = NULL;

	bpf_probe_read_kernel(&private_data, sizeof(private_data),
			      file + offset->struct_files_private_data_offset);
	if (private_data == NULL) {
		return NULL;
	}

	struct socket *socket = (struct socket*)private_data;
	short socket_type;
	void* check_file;
	void *sk;
	struct socket __socket;
	bpf_probe_read_kernel(&__socket, sizeof(__socket), (void *)socket);

	socket_type = __socket.type;
	if (__socket.file != file) {
		check_file = &__socket.wq;	// kernel >= 5.3.0 remove '*wq'
		sk = __socket.file;
	} else {
		check_file = __socket.file;
		sk = __socket.sk;
	}
	if ((socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) &&
	    check_file == file /*&& __socket.state == SS_CONNECTED */ ) {
		return sk;
	}

	return NULL;
}