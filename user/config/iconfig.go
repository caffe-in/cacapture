package config

type IConfig interface {
	Check() error //检测配置合法性
	GetPid() uint64
	GetUid() uint64
	GetHex() bool
	GetDebug() bool
	SetPid(uint64)
	SetUid(uint64)
	SetHex(bool)
	SetDebug(bool)
	SetPort(uint16)
	GetPerCpuMapSize() int
	SetPerCpuMapSize(int)
	EnableGlobalVar() bool //
}

type eConfig struct {
	Pid           uint64
	Uid           uint64
	PerCpuMapSize int // ebpf map size for per Cpu.   see https://github.com/gojue/ecapture/issues/433 .
	IsHex         bool
	Debug         bool
	Port          uint16
}
