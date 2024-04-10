#include <sys/resource.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tc.skel.h"

#define MAX_PACKET_SIZE 2048
#define DEST_UDP_IP "127.0.0.1"
#define DEST_UDP_PORT 12345

static int open_udp_socket(const char *ip, int port) {
    struct sockaddr_in servaddr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    int udp_sock = *(int *)ctx;
    send(udp_sock, data, data_sz, 0); // 发送数据
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv) {
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb = NULL;
    struct bpf_object *obj = NULL;
    int udp_sock, bpf_fd;
    const char *bpf_file = "test.o"; // 替换为你的eBPF编译后的文件名

    // 提升资源限制
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    // 打开UDP套接字
    udp_sock = open_udp_socket(DEST_UDP_IP, DEST_UDP_PORT);

    // 加载并附加eBPF程序
    obj = bpf_object__open_file(bpf_file, NULL);
    if (libbpf_get_error(obj)) {
        perror("Failed to open BPF object");
        return 1;
    }

    if (bpf_object__load(obj)) {
        perror("Failed to load BPF object");
        return 1;
    }

    // 获取skb_events地图的文件描述符
    bpf_fd = bpf_object__find_map_fd_by_name(obj, "skb_events");
    if (bpf_fd < 0) {
        perror("Failed to find skb_events map");
        return 1;
    }

    // 设置性能缓冲区选项
    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost_events;
    pb_opts.ctx = &udp_sock;

    // 创建并启动性能缓冲区
    pb = perf_buffer__new(bpf_fd, 64, &pb_opts);
    if (libbpf_get_error(pb)) {
        perror("Failed to create perf buffer");
        return 1;
    }

    // 主事件循环
    while ((errno = perf_buffer__poll(pb, 1000)) >= 0) {
        // 你可以在这个循环中添加更多功能
        printf("Received %d events\n", errno);
    }

    // 清理
    perf_buffer__free(pb);
    bpf_object__close(obj);
    close(udp_sock);

    return 0;
}