package container

import (
	"sync"
)

// 定义容器状态
type ContainerState struct {
	Mutex          sync.Mutex
	ContainerID    string
	PID            int
	PodName        string // Pod 名称
	Namespace      string // Namespace 名称
	ContainerName  string // 容器名称
	SyscallCount   map[string]int
	FileOperations map[uint64]*FileOperationStats `json:"file_operations"` // 按文件路径分类的文件操作统计

	// Mount 信息
	SuccessfulMountNum int
	FailedMountNum     int
	FsMountStats       map[string]*FsMountStats
	MountHistory       []string
}

// 每个文件的操作统计信息
type FileOperationStats struct {
	Filename        string                `json:"filename"`          // 文件名
	TotalReads      uint64                `json:"total_reads"`       // 读操作总次数
	TotalReadBytes  uint64                `json:"total_read_bytes"`  // 读操作总字节数
	TotalWrites     uint64                `json:"total_writes"`      // 写操作总次数
	TotalWriteBytes uint64                `json:"total_write_bytes"` // 写操作总字节数
	Operations      []FileOperationDetail `json:"operations"`        // 每次操作的详细信息
}

// 单次文件操作的详细信息
type FileOperationDetail struct {
	Type      string `json:"type"`      // 操作类型 ("read" 或 "write")
	Bytes     uint64 `json:"bytes"`     // 本次操作读/写的字节数
	Timestamp int64  `json:"timestamp"` // 操作发生的时间戳（UNIX 时间）
}

// 记录某个文件系统的挂载统计信息
type FsMountStats struct {
	SuccessCount int // 成功挂载次数
	FailedCount  int // 失败挂载次数
}
