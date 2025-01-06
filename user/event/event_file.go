package event

import (
	"bytes"
	"cacapture/user/container"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	PATH_MAX           = 4096
	FILE_TASK_COMM_LEN = 16
)

type FileEvent struct {
	eventType EventType
	Inode     uint64                   // 文件 inode
	PID       uint32                   // 进程 ID
	TID       uint32                   // 线程 ID
	Filename  [PATH_MAX]byte           // 文件名
	Comm      [FILE_TASK_COMM_LEN]byte // 进程名
	Operation byte                     // 操作类型 ('R' for read, 'W' for write)
	Bytes     uint64                   // 操作的字节数
}

func (fe *FileEvent) Decode(payload []byte) (err error) {
	// buf := bytes.NewBuffer(payload)
	reader := bytes.NewReader(payload)
	// 读取文件 inode
	if err = binary.Read(reader, binary.LittleEndian, &fe.Inode); err != nil {
		return
	}
	// 读取进程 ID
	if err = binary.Read(reader, binary.LittleEndian, &fe.PID); err != nil {
		return
	}
	// 读取线程 ID
	if err = binary.Read(reader, binary.LittleEndian, &fe.TID); err != nil {
		return
	}
	// 读取文件名
	if err = binary.Read(reader, binary.LittleEndian, &fe.Filename); err != nil {
		return
	}
	// 读取进程名
	if err = binary.Read(reader, binary.LittleEndian, &fe.Comm); err != nil {
		return
	}
	// 读取操作类型
	if err = binary.Read(reader, binary.LittleEndian, &fe.Operation); err != nil {
		return
	}
	// 跳过 7 字节 padding (总共 8 字节对齐 1operation+7padding)
	if _, err = reader.Seek(7, io.SeekCurrent); err != nil {
		return fmt.Errorf("error seeking padding: %w", err)
	}

	if err = binary.Read(reader, binary.LittleEndian, &fe.Bytes); err != nil {
		return fmt.Errorf("error reading Bytes: %w", err)
	}
	return
}

func (fe *FileEvent) StringHex() string {

	return ""
}

func (fe *FileEvent) GetFilename() string {
	nullIndex := bytes.IndexByte(fe.Filename[:], 0) // 找到第一个 '\x00'
	if nullIndex == -1 {
		return string(fe.Filename[:]) // 如果没有 '\x00'，返回整个缓冲区
	}
	return string(fe.Filename[:nullIndex]) // 截断到第一个 '\x00'
}
func (fe *FileEvent) String() string {
	filename := fe.GetFilename()
	comm := strings.TrimRight(string(fe.Comm[:]), "\x00")
	s := fmt.Sprintf("FileEvent: PID=%d, TID=%d, FileInode=%d,Filename=%s (Length=%d), Comm=%s, Operation=%c, Bytes=%d",
		fe.PID, fe.TID, fe.Inode, filename, len(filename), comm, fe.Operation, fe.Bytes)
	return s
}

func (fe *FileEvent) Clone() IEventStruct {
	event := new(FileEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (fe *FileEvent) EventType() EventType {
	return fe.eventType
}

func (fe *FileEvent) GetUUID() string {
	return ""
}

func (fe *FileEvent) Payload() []byte {
	return []byte{}
}

// FileEvent has no payload
func (fe *FileEvent) PayloadLen() int {
	return 0
}

func (fe *FileEvent) GetPid() int {
	return int(fe.PID)
}

func (fe *FileEvent) UpdateContainerState(state *container.ContainerState) *container.ContainerState {
	// 将文件名从 [PATH_MAX]byte 转换为字符串，并去除空字符
	filename := fe.GetFilename()

	// 初始化文件统计信息（如果不存在）
	if state.FileOperations == nil {
		state.FileOperations = make(map[uint64]*container.FileOperationStats)
	}
	if _, exists := state.FileOperations[fe.Inode]; !exists {
		state.FileOperations[fe.Inode] = &container.FileOperationStats{
			Filename: filename,
		}
	}

	stats := state.FileOperations[fe.Inode]

	// 更新汇总统计
	switch fe.Operation {
	case 'R': // 读操作
		stats.TotalReads++
		stats.TotalReadBytes += fe.Bytes
	case 'W': // 写操作
		stats.TotalWrites++
		stats.TotalWriteBytes += fe.Bytes
	}

	// 添加操作详情
	detail := container.FileOperationDetail{
		Type:      map[byte]string{'R': "read", 'W': "write"}[fe.Operation],
		Bytes:     fe.Bytes,
		Timestamp: time.Now().Unix(),
	}
	stats.Operations = append(stats.Operations, detail)

	return state
}
