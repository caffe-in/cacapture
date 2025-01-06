package event

import (
	"bytes"
	"cacapture/user/container"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	MOUNT_TASK_COMM_LEN = 16
	FS_NAME_LEN         = 8
	DATA_LEN            = 512
)

// 定义 MountOp 类型（等效于 C 中的 `enum mount_op`）
type MountOp uint8

const (
	Mount   MountOp = iota // 对应 C 中的 MOUNT
	Umount                 // 对应 C 中的 UMOUNT
	Remount                // 对应 C 中的 REMOUNT
)

// 定义 Go 的 MountEvent 结构体
type MountEvent struct {
	eventType EventType
	Delta     uint64                    // 挂载操作耗时
	Flags     uint64                    // 挂载标志
	PID       uint32                    // 发起挂载操作的进程 ID
	TID       uint32                    // 发起挂载操作的线程 ID
	MntNS     uint32                    // 挂载命名空间 ID
	Ret       int32                     // 系统调用返回值
	Comm      [MOUNT_TASK_COMM_LEN]byte // 进程名（固定长度数组）
	FS        [FS_NAME_LEN]byte         // 文件系统类型
	Src       [PATH_MAX]byte            // 源路径
	Dest      [PATH_MAX]byte            // 挂载点路径
	Data      [DATA_LEN]byte            // 挂载附加数据
	Op        MountOp                   // 挂载操作类型（枚举）
}

func (me *MountEvent) Decode(payload []byte) (err error) {
	// buf := bytes.NewBufmer(payload)
	reader := bytes.NewReader(payload)
	fmt.Println("start decode mount event")
	// 读取挂载操作耗时
	if err = binary.Read(reader, binary.LittleEndian, &me.Delta); err != nil {
		return err
	}
	// 读取挂载标志
	if err = binary.Read(reader, binary.LittleEndian, &me.Flags); err != nil {
		return err
	}
	// 读取进程 ID
	if err = binary.Read(reader, binary.LittleEndian, &me.PID); err != nil {
		return err
	}
	// 读取线程 ID
	if err = binary.Read(reader, binary.LittleEndian, &me.TID); err != nil {
		return err
	}
	// 读取挂载命名空间 ID
	if err = binary.Read(reader, binary.LittleEndian, &me.MntNS); err != nil {
		return err
	}
	// 读取系统调用返回值
	if err = binary.Read(reader, binary.LittleEndian, &me.Ret); err != nil {
		return err
	}
	// 读取进程名
	if err = binary.Read(reader, binary.LittleEndian, &me.Comm); err != nil {
		return err
	}
	// 读取文件系统类型
	if err = binary.Read(reader, binary.LittleEndian, &me.FS); err != nil {
		return err
	}
	// 读取源路径
	if err = binary.Read(reader, binary.LittleEndian, &me.Src); err != nil {
		return err
	}
	// 读取挂载点路径
	if err = binary.Read(reader, binary.LittleEndian, &me.Dest); err != nil {
		return err
	}
	// 读取挂载附加数据
	if err = binary.Read(reader, binary.LittleEndian, &me.Data); err != nil {
		return err
	}
	// 读取挂载操作类型
	if err = binary.Read(reader, binary.LittleEndian, &me.Op); err != nil {
		return err
	}
	return
}

func (me *MountEvent) StringHex() string {

	return ""
}

func (me *MountEvent) String() string {

	comm := strings.TrimRight(string(me.Comm[:]), "\x00")
	s := fmt.Sprintf("MountEvent: PID=%d, TID=%d, MntNS=%d, Delta=%d, Flags=%d, Ret=%d, Comm=%s, FS=%s, Src=%s, Dest=%s, Data=%s, Op=%d",
		me.Delta, me.Flags, me.PID, me.TID, me.MntNS, me.Ret, comm, me.FS, me.Src, me.Dest, me.Data, me.Op)
	return s
}

func (me *MountEvent) Clone() IEventStruct {
	event := new(MountEvent)
	event.eventType = EventTypeOutput
	return event
}

func (me *MountEvent) EventType() EventType {
	return me.eventType
}

func (me *MountEvent) GetUUID() string {
	return ""
}

func (me *MountEvent) Payload() []byte {
	return []byte{}
}

// MountEvent has no payload
func (me *MountEvent) PayloadLen() int {
	return 0
}

func (me *MountEvent) GetPid() int {
	return int(me.PID)
}

func (me *MountEvent) Descripe(state *container.ContainerState) string {
	containerName := state.ContainerName
	podName := state.PodName
	namespace := state.Namespace
	if containerName == "" {
		containerName = "unknown"
	}
	comm := strings.TrimRight(string(me.Comm[:]), "\x00")
	var op string
	switch me.Op {
	case Mount:
		op = "mount"
	case Umount:
		op = "umount"
	case Remount:
		op = "remount"
	default:
		op = "unknown"
	}
	s := fmt.Sprintf("MountEvent:  ContainerName=%s, PodName=%s, Namespace=%s, Type=%s, Delta=%d, Flags=%d, Ret=%d, Comm=%s, FS=%s, Src=%s, Dest=%s, Data=%s",
		&containerName, &podName, &namespace, &op, me.Delta, me.Flags, me.Ret, comm, me.FS, me.Src, me.Dest, me.Data)
	return s

}

func (me *MountEvent) UpdateContainerState(state *container.ContainerState) *container.ContainerState {
	state.Mutex.Lock()
	defer state.Mutex.Unlock()

	// 判断挂载是否成功
	if me.Ret == 0 {
		state.SuccessfulMountNum++ // 成功挂载次数加一
	} else {
		state.FailedMountNum++ // 失败挂载次数加一
	}

	// 按文件系统类型更新统计信息
	fsType := string(me.FS[:]) // 获取文件系统类型
	if _, exists := state.FsMountStats[fsType]; !exists {
		// 如果该文件系统类型尚未记录，初始化统计数据
		state.FsMountStats[fsType] = &container.FsMountStats{}
	}
	if me.Ret == 0 {
		state.FsMountStats[fsType].SuccessCount++ // 成功挂载次数
	} else {
		state.FsMountStats[fsType].FailedCount++ // 失败挂载次数
	}
	// 将挂载事件添加到历史记录中
	serializedEvent := me.Descripe(state)
	state.MountHistory = append(state.MountHistory, serializedEvent)

	// 限制历史记录的长度（例如保留最近 10 条）
	if len(state.MountHistory) > 10 {
		state.MountHistory = state.MountHistory[1:]
	}
	fmt.Println("update container state mount successful")

	return state
}
