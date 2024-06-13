[TOC]

## Deepflow七层协议dns和http的移植说明

- 目前移植进度到达可以编译kern 代码，但是kern 代码无法加载通过ebpf vertifer，由此user code也未完成
- 更多相关描述请参看[deepflow agent ebpf code说明](https://github.com/deepflowio/deepflow/blob/main/agent/src/ebpf/README.md)



### 编译方法

```sh
make socket
make asset-socket
```

将会在kern文件夹中出现socket.o库



### Code Explain

- 重要文件

  - socket.bpf.c
  - include/maps.h
  - incude/protocol_inference.h

- 方法流程

  - 调用入口

    ```c
    SEC("tracepoint/syscalls/sys_enter_write");	//在系统调用前保存相关args至args_map
    ```

  - 调用出口

    ```c
    SEC("tracepoint/syscalls/sys_exit_write"); //读取该系统调用args_map中的args 并调用
    process_syscall_data((struct pt_regs *)ctx, id, T_EGRESS,
    							 write_args, bytes_count);
    ```

  - 系统调用处理

    ```c
    static __inline void process_syscall_data((struct pt_regs *)ctx, id, T_EGRESS,
    							 write_args, bytes_count);
    // 处理数据--->调用func process_data(ctx, id, direction, args, bytes_count, &extra);
    // 提交数据--->调用proggtp_data_submit(ctx);
    ```

  - 处理数据

    ```c
    static __inline int process_data(struct pt_regs *ctx, __u64 id,
    								 const enum traffic_direction direction,
    								 const struct data_args_t *args,
    								 ssize_t bytes_count,
    								 const struct process_data_extra *extra);
    // 推理7层协议 ---> act = infer_l7_class(ctx_map, conn_info, direction, args,
    							 bytes_count, sock_state, extra);
    ```

  - 提交数据

    ```c
    static inline proggtp_data_submit(void *ctx);
    // 处理并形成sock_data -->ret = data_submit(ctx);
    // 将socket_data perf 到 socket_perf_event_map等待用户提取-->progtp_output_data(ctx);
    ```

    