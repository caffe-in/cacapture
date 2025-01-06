#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "include/bpf_core_read.h"
#include "include/bpf_tracing.h"
#include "mountsnoop.h"

// #define MAX_ENTRIES 10240

const volatile pid_t mount_target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct arg);
} args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);      // 环形缓冲区类型
    __uint(max_entries, 1 << 24);           // 环形缓冲区大小（16MB）
} mount_events SEC(".maps");

static int mount_probe_entry(const char *src, const char *dest, const char *fs,
		       __u64 flags, const char *data, enum mount_op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg arg = {};

	if (mount_target_pid && mount_target_pid != pid)
		return 0;

	arg.ts = bpf_ktime_get_ns();
	arg.flags = flags;
	arg.src = src;
	arg.dest = dest;
	arg.fs = fs;
	arg.data= data;
	arg.op = op;
	bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);
	return 0;
};

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg *argp;
	struct event *eventp;
	struct task_struct *task;
	int zero = 0;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

    // 分配事件结构体空间
    eventp = bpf_ringbuf_reserve(&mount_events, sizeof(*eventp), 0);
    if (!eventp)
        return 0;  // 如果分配失败，直接退出

	task = (struct task_struct *)bpf_get_current_task();
	eventp->delta = bpf_ktime_get_ns() - argp->ts;
	eventp->flags = argp->flags;
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	eventp->ret = ret;
	eventp->op = argp->op;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	if (argp->src)
		bpf_probe_read_user_str(eventp->src, sizeof(eventp->src), argp->src);
	else
		eventp->src[0] = '\0';
	if (argp->dest)
		bpf_probe_read_user_str(eventp->dest, sizeof(eventp->dest), argp->dest);
	else
		eventp->dest[0] = '\0';
	if (argp->fs)
		bpf_probe_read_user_str(eventp->fs, sizeof(eventp->fs), argp->fs);
	else
		eventp->fs[0] = '\0';
	if (argp->data)
		bpf_probe_read_user_str(eventp->data, sizeof(eventp->data), argp->data);
	else
		eventp->data[0] = '\0';
    // 提交事件到 ringbuf
	bpf_printk("mountsnoop, pid: %d, tid: %d,ret: %d\n",
		   pid, tid, ret);
    bpf_ringbuf_submit(eventp, 0);

	bpf_map_delete_elem(&args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int mount_entry(struct trace_event_raw_sys_enter *ctx)
{
	const char *src = (const char *)ctx->args[0];
	const char *dest = (const char *)ctx->args[1];
	const char *fs = (const char *)ctx->args[2];
	__u64 flags = (__u64)ctx->args[3];
	const char *data = (const char *)ctx->args[4];

	return mount_probe_entry(src, dest, fs, flags, data, MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_mount")
int mount_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int umount_entry(struct trace_event_raw_sys_enter *ctx)
{
	const char *dest = (const char *)ctx->args[0];
	__u64 flags = (__u64)ctx->args[1];

	return mount_probe_entry(NULL, dest, NULL, flags, NULL, UMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_umount")
int umount_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}