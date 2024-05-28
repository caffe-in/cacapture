#!/bin/bash

# 检查输入参数
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <process-name>"
    exit 1
fi

process_name=$1

# 查找所有匹配的进程 PID
pids=$(pgrep -f "(^|/)$process_name( |$)")
if [ -z "$pids" ]; then
    echo "No processes found with name: $process_name"
    exit 1
fi

echo "Found PIDs:"
echo "$pids"
for pid in $pids; do
    echo $pid | sudo tee /sys/fs/cgroup/caffein_cgroup/cgroup.procs
done

echo "Processes added to cgroup successfully."