#include "vmlinux.h"
#include <linux/limits.h>

#define BPF_MAX_LOG_FILE_LEN 72
#define MAX_BIN_PATH_SIZE 256
#define MAX_CACHED_PATH_SIZE 64
enum bpf_log_level
{
    BPF_LOG_LVL_DEBUG = -1,
    BPF_LOG_LVL_INFO,
    BPF_LOG_LVL_WARN,
    BPF_LOG_LVL_ERROR,
};

enum bpf_log_id
{
    BPF_LOG_ID_UNSPEC = 0U, // enforce enum to u32

    // tracee functions
    BPF_LOG_ID_INIT_CONTEXT,

    // bpf helpers functions
    BPF_LOG_ID_MAP_LOOKUP_ELEM,
    BPF_LOG_ID_MAP_UPDATE_ELEM,
    BPF_LOG_ID_MAP_DELETE_ELEM,
    BPF_LOG_ID_GET_CURRENT_COMM,
    BPF_LOG_ID_TAIL_CALL,
    BPF_LOG_ID_MEM_READ,

    // hidden kernel module functions
    BPF_LOG_ID_HID_KER_MOD,
};
enum event_id_e
{
    // Net events IDs
    NET_PACKET_BASE = 700,
    NET_PACKET_IP,
    NET_PACKET_TCP,
    NET_PACKET_UDP,
    NET_PACKET_ICMP,
    NET_PACKET_ICMPV6,
    NET_PACKET_DNS,
    NET_PACKET_HTTP,
    NET_CAPTURE_BASE,
    NET_FLOW_BASE,
    MAX_NET_EVENT_ID,
    // Common event IDs
    RAW_SYS_ENTER,
    RAW_SYS_EXIT,
    SCHED_PROCESS_FORK,
    SCHED_PROCESS_EXEC,
    SCHED_PROCESS_EXIT,
    SCHED_SWITCH,
    DO_EXIT,
    CAP_CAPABLE,
    VFS_WRITE,
    VFS_WRITEV,
    VFS_READ,
    VFS_READV,
    MEM_PROT_ALERT,
    COMMIT_CREDS,
    SWITCH_TASK_NS,
    MAGIC_WRITE,
    CGROUP_ATTACH_TASK,
    CGROUP_MKDIR,
    CGROUP_RMDIR,
    SECURITY_BPRM_CHECK,
    SECURITY_FILE_OPEN,
    SECURITY_INODE_UNLINK,
    SECURITY_SOCKET_CREATE,
    SECURITY_SOCKET_LISTEN,
    SECURITY_SOCKET_CONNECT,
    SECURITY_SOCKET_ACCEPT,
    SECURITY_SOCKET_BIND,
    SECURITY_SOCKET_SETSOCKOPT,
    SECURITY_SB_MOUNT,
    SECURITY_BPF,
    SECURITY_BPF_MAP,
    SECURITY_KERNEL_READ_FILE,
    SECURITY_INODE_MKNOD,
    SECURITY_POST_READ_FILE,
    SECURITY_INODE_SYMLINK,
    SECURITY_MMAP_FILE,
    SECURITY_FILE_MPROTECT,
    SOCKET_DUP,
    HIDDEN_INODES,
    __KERNEL_WRITE,
    PROC_CREATE,
    KPROBE_ATTACH,
    CALL_USERMODE_HELPER,
    DIRTY_PIPE_SPLICE,
    DEBUGFS_CREATE_FILE,
    SYSCALL_TABLE_CHECK,
    DEBUGFS_CREATE_DIR,
    DEVICE_ADD,
    REGISTER_CHRDEV,
    SHARED_OBJECT_LOADED,
    DO_INIT_MODULE,
    SOCKET_ACCEPT,
    LOAD_ELF_PHDRS,
    HOOKED_PROC_FOPS,
    PRINT_NET_SEQ_OPS,
    TASK_RENAME,
    SECURITY_INODE_RENAME,
    DO_SIGACTION,
    BPF_ATTACH,
    KALLSYMS_LOOKUP_NAME,
    DO_MMAP,
    PRINT_MEM_DUMP,
    VFS_UTIMES,
    DO_TRUNCATE,
    FILE_MODIFICATION,
    INOTIFY_WATCH,
    SECURITY_BPF_PROG,
    PROCESS_EXECUTION_FAILED,
    SECURITY_PATH_NOTIFY,
    SET_FS_PWD,
    HIDDEN_KERNEL_MODULE_SEEKER,
    MODULE_LOAD,
    MODULE_FREE,
    EXECUTE_FINISHED,
    SECURITY_BPRM_CREDS_FOR_EXEC,
    MAX_EVENT_ID,
    NO_EVENT_SUBMIT,
};
typedef struct task_context {
    u64 start_time;               // task's start time
    u64 cgroup_id;                // control group ID
    u32 pid;                      // PID as in the userspace term
    u32 tid;                      // TID as in the userspace term
    u32 ppid;                     // Parent PID as in the userspace term
    u32 host_pid;                 // PID in host pid namespace
    u32 host_tid;                 // TID in host pid namespace
    u32 host_ppid;                // Parent PID in host pid namespace
    u32 uid;                      // task's effective UID
    u32 mnt_id;                   // task's mount namespace ID
    u32 pid_id;                   // task's pid namespace ID
    char comm[TASK_COMM_LEN];     // task's comm
    char uts_name[TASK_COMM_LEN]; // task's uts name
    u32 flags;                    // task's status flags (see context_flags_e)
    u64 leader_start_time;        // task leader's monotonic start time
    u64 parent_start_time;        // parent process task leader's monotonic start time
} task_context_t;

typedef struct args {
    unsigned long args[6];
} args_t;

typedef struct syscall_data {
    uint id;           // Current syscall id
    args_t args;       // Syscall arguments
    unsigned long ts;  // Timestamp of syscall entry
    unsigned long ret; // Syscall ret val. May be used by syscall exit tail calls.
} syscall_data_t;


typedef struct task_info {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced; // indicates that syscall_data is valid
    u8 container_state;  // the state of the container the task resides in
} task_info_t;

typedef union scratch {
    bpf_log_output_t log_output;
    proc_info_t proc_info;
    task_info_t task_info;
} scratch_t;

typedef struct bpf_log_output {
    enum bpf_log_id id; // type
    enum bpf_log_level level;
    u32 count;
    u32 padding;
    struct bpf_log log;
} bpf_log_output_t;

typedef struct bpf_log {
    s64 ret; // return value
    u32 cpu;
    u32 line;                        // line number
    char file[BPF_MAX_LOG_FILE_LEN]; // filename
} bpf_log_t;

typedef struct proc_info {
    bool new_proc;        // set if this process was started after tracee. Used with new_pid filter
    u64 follow_in_scopes; // set if this process was traced before. Used with the follow filter
    struct binary binary;
    u32 binary_no_mnt; // used in binary lookup when we don't care about mount ns. always 0.
    file_info_t interpreter;
} proc_info_t;

typedef struct binary {
    u32 mnt_id;
    char path[MAX_BIN_PATH_SIZE];
} binary_t;
typedef struct file_info {
    union {
        char pathname[MAX_CACHED_PATH_SIZE];
        char *pathname_p;
    };
    file_id_t id;
} file_info_t;

typedef struct file_id {
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_id_t;

typedef struct policies_config {
    // enabled scopes bitmask per filter
    u64 uid_filter_enabled_scopes;
    u64 pid_filter_enabled_scopes;
    u64 mnt_ns_filter_enabled_scopes;
    u64 pid_ns_filter_enabled_scopes;
    u64 uts_ns_filter_enabled_scopes;
    u64 comm_filter_enabled_scopes;
    u64 cgroup_id_filter_enabled_scopes;
    u64 cont_filter_enabled_scopes;
    u64 new_cont_filter_enabled_scopes;
    u64 new_pid_filter_enabled_scopes;
    u64 proc_tree_filter_enabled_scopes;
    u64 bin_path_filter_enabled_scopes;
    u64 follow_filter_enabled_scopes;
    // filter_out bitmask per filter
    u64 uid_filter_out_scopes;
    u64 pid_filter_out_scopes;
    u64 mnt_ns_filter_out_scopes;
    u64 pid_ns_filter_out_scopes;
    u64 uts_ns_filter_out_scopes;
    u64 comm_filter_out_scopes;
    u64 cgroup_id_filter_out_scopes;
    u64 cont_filter_out_scopes;
    u64 new_cont_filter_out_scopes;
    u64 new_pid_filter_out_scopes;
    u64 proc_tree_filter_out_scopes;
    u64 bin_path_filter_out_scopes;
    // bitmask with scopes that have at least one filter enabled
    u64 enabled_scopes;
    // global min max
    u64 uid_max;
    u64 uid_min;
    u64 pid_max;
    u64 pid_min;
} policies_config_t;

typedef struct config_entry {
    u32 tracee_pid;
    u32 options;
    u32 cgroup_v1_hid;
    u16 padding; // free for further use
    u16 policies_version;
    policies_config_t policies_config;
} config_entry_t;

typedef struct program_data {
    config_entry_t *config;
    task_info_t *task_info;
    proc_info_t *proc_info;
    event_data_t *event;
    u32 scratch_idx;
    void *ctx;
} program_data_t;

typedef struct args_buffer {
    u8 argnum;
    char args[ARGS_BUF_SIZE];
    u32 offset;
} args_buffer_t;
typedef struct syscall_event_data{
    args_buffer_t args_buf;
}
typedef struct event_context {
    u64 ts; // timestamp
    task_context_t task;
    u32 eventid;
    s32 syscall; // syscall that triggered the event
    s64 retval;
    u32 stack_id;
    u16 processor_id; // ID of the processor that processed the event
    u16 policies_version;
    u64 matched_policies;
} event_context_t;

typedef struct event_config {
    u64 submit_for_policies;
    u64 param_types;
} event_config_t;

typedef struct event_data {
    event_context_t context;
    args_buffer_t args_buf;
    struct task_struct *task;
    event_config_t config;
    policies_config_t policies_config;
} event_data_t;