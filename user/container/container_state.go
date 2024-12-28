package container

// 定义容器状态
type ContainerState struct {
	ContainerID   string
	PID           int
	PodName       string // Pod 名称
	Namespace     string // Namespace 名称
	ContainerName string // 容器名称
	SyscallCount  map[string]int
}
