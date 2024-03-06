package config

import (
	"os"

	"github.com/gojue/ebpfmanager/kernel"
)

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

func (c *eConfig) GetPid() uint64 {
	return c.Pid
}

func (c *eConfig) GetUid() uint64 {
	return c.Uid
}

func (c *eConfig) GetDebug() bool {
	return c.Debug
}

func (c *eConfig) GetHex() bool {
	return c.IsHex
}

func (c *eConfig) SetPid(pid uint64) {
	c.Pid = pid
}

func (c *eConfig) SetUid(uid uint64) {
	c.Uid = uid
}

func (c *eConfig) SetDebug(b bool) {
	c.Debug = b
}

func (c *eConfig) SetHex(isHex bool) {
	c.IsHex = isHex
}
func (c *eConfig) SetPort(port uint16) {
	c.Port = port
}
func (c *eConfig) GetPerCpuMapSize() int {
	return c.PerCpuMapSize
}

func (c *eConfig) SetPerCpuMapSize(size int) {
	c.PerCpuMapSize = size * os.Getpagesize()
}

func (c *eConfig) EnableGlobalVar() bool {
	kv, err := kernel.HostVersion()
	if err != nil {
		//log.Fatal(err)
		return true
	}
	if kv < kernel.VersionCode(5, 2, 0) {
		return false
	}
	return true
}
