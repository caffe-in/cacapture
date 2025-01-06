/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "include/bpf_core_read.h"
#include "include/bpf_tracing.h"
#include "files.h"
#include "stat.h"

#define FILES_MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
const volatile bool regular_file_only = true;
static struct file_stat zero_value = {};

struct file_event
{
	__u64 inode;			  // 文件 inode
	__u32 pid;				  // 进程 ID
	__u32 tid;				  // 线程 ID
	char filename[PATH_MAX];  // 文件名
	char comm[TASK_COMM_LEN]; // 进程名
	char operation;			  // 操作类型 ('R' for read, 'W' for write)
	__u64 bytes;			  // 操作的字节数
};
static struct file_event zero_event = {}; // 初始化为全 0
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16MB Ring Buffer
} file_events SEC(".maps");

static void get_file_path(struct file *file, char *buf, size_t size)
{
	struct qstr dname;

	dname = BPF_CORE_READ(file, f_path.dentry, d_name);
	bpf_probe_read_kernel(buf, size, dname.name);
}

static __always_inline void get_full_path(struct file *file, char *buf, int buf_size)
{
	if (!file || !buf || buf_size <= 0)
		return;

	struct path file_path;
	bpf_core_read(&file_path, sizeof(file_path), &file->f_path);

	// 使用 bpf_d_path 获取完整路径
	long ret = bpf_d_path(&file_path, buf, buf_size);

	// 确保路径以 '\0' 结尾（防止 bpf_d_path 返回负值时未处理）
	if (ret < 0)
	{
		buf[0] = '\0'; // 如果失败，将路径置为空字符串
	}
	else
	{
		buf[buf_size - 1] = '\0'; // 确保路径以 '\0' 结尾
	}
}

static int file_probe_entry(struct pt_regs *ctx, struct file *file, size_t count, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	int mode;
	struct file_id key = {};
	struct file_event *event;

	if (target_pid && target_pid != pid)
		return 0;

	mode = BPF_CORE_READ(file, f_inode, i_mode);
	if (regular_file_only && !S_ISREG(mode))
		return 0;

	// 从 Ring Buffer 分配一块内存
	event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
	if (!event)
		return 0;
	// 填充事件信息
	bpf_probe_read_kernel(event, sizeof(*event), &zero_event);
	event->inode = BPF_CORE_READ(file, f_inode, i_ino);
	event->pid = pid;
	event->tid = tid;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	get_file_path(file, event->filename, sizeof(event->filename));



	event->operation = (op == READ) ? 'R' : 'W';
	event->bytes = count;
#define TRACE_PIPE "trace_pipe"
#define TRACE_PIPE_LEN 10 // strlen("trace_pipe")

	if (event->filename[0] != '\0')
	{						   // 确保文件名非空
		int is_trace_pipe = 1; // 假设是 trace_pipe

		// 逐字符比较
		for (int i = 0; i < TRACE_PIPE_LEN; i++)
		{
			if (event->filename[i] != TRACE_PIPE[i])
			{
				is_trace_pipe = 0; // 如果有任何一个字符不匹配，则不是 trace_pipe
				break;
			}
		}

		// 检查文件名是否刚好结束（以 '\0' 结束，且长度等于 TRACE_PIPE_LEN）
		if (event->filename[TRACE_PIPE_LEN] != '\0')
		{
			is_trace_pipe = 0;
		}

		// // 如果匹配 trace_pipe，则跳过打印
		// if (!is_trace_pipe)
		// {
		// 	bpf_printk("DEBUG: Bytes written: %llu\n", event->bytes);
		// }
	}
#undef TRACE_PIPE

	// if (op == READ)
	// {
	// 	event->reads++;
	// 	event->read_bytes += count;
	// }
	// else
	// { // WRITE
	// 	event->writes++;
	// 	event->write_bytes += count;
	// }

	// key.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
	// key.rdev = BPF_CORE_READ(file, f_inode, i_rdev);
	// key.inode = BPF_CORE_READ(file, f_inode, i_ino);
	// key.pid = pid;
	// key.tid = tid;
	// valuep = bpf_map_lookup_elem(&file_events, &key);
	// if (!valuep)
	// {
	// 	bpf_map_update_elem(&file_events, &key, &zero_value, BPF_ANY);
	// 	valuep = bpf_map_lookup_elem(&file_events, &key);
	// 	if (!valuep)
	// 		return 0;
	// 	valuep->pid = pid;
	// 	valuep->tid = tid;
	// 	bpf_get_current_comm(&valuep->comm, sizeof(valuep->comm));
	// 	get_file_path(file, valuep->filename, sizeof(valuep->filename));
	// 	if (S_ISREG(mode))
	// 	{
	// 		valuep->type = 'R';
	// 	}
	// 	else if (S_ISSOCK(mode))
	// 	{
	// 		valuep->type = 'S';
	// 	}
	// 	else
	// 	{
	// 		valuep->type = 'O';
	// 	}
	// }
	// if (op == READ)
	// {
	// 	valuep->reads++;
	// 	valuep->read_bytes += count;
	// }
	// else
	// { /* op == WRITE */
	// 	valuep->writes++;
	// 	valuep->write_bytes += count;
	// }
	bpf_ringbuf_submit(event, 0);
	return 0;
};

SEC("kprobe/vfs_read")
int vfs_read(struct pt_regs *ctx)
{
	// 提取参数
#if defined(__TARGET_ARCH_x86_64)
	struct file *file = (struct file *)ctx->di; // 第一个参数
	size_t count = (size_t)ctx->dx;				// 第三个参数
#elif defined(__TARGET_ARCH_aarch64)
	struct file *file = (struct file *)ctx->regs[0];
	char __user *buf = (char __user *)ctx->regs[1];
	size_t count = (size_t)ctx->regs[2];
	loff_t *pos = (loff_t *)ctx->regs[3];
#else
#error "Unsupported architecture"
#endif
	return file_probe_entry(ctx, file, count, READ);
}
SEC("kprobe/vfs_write")
int vfs_write(struct pt_regs *ctx)
{
	// 提取参数

#if defined(__TARGET_ARCH_x86_64)
	struct file *file = (struct file *)ctx->di; // 第一个参数
	size_t count = (size_t)ctx->dx;				// 第三个参数
#elif defined(__TARGET_ARCH_aarch64)
	struct file *file = (struct file *)ctx->regs[0];
	char __user *buf = (char __user *)ctx->regs[1];
	size_t count = (size_t)ctx->regs[2];
	loff_t *pos = (loff_t *)ctx->regs[3];
#else
#error "Unsupported architecture"
#endif
	return file_probe_entry(ctx, file, count, WRITE);
}
// SEC("kprobe/vfs_read")
// int BPF_KPROBE(vfs_read_entry, struct file *file, char *buf, size_t count, loff_t *pos)
// {
// 	return file_probe_entry(ctx, file, count, READ);
// }

// SEC("kprobe/vfs_write")
// int BPF_KPROBE(vfs_write_entry, struct file *file, const char *buf, size_t count, loff_t *pos)
// {
// 	return file_probe_entry(ctx, file, count, WRITE);
// }