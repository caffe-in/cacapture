package config

import (
	"os"

	"github.com/gojue/ebpfmanager/kernel"
	"github.com/vishvananda/netns"
)

type IConfig interface {
	GetPerCpuMapSize() int
	SetPerCpuMapSize(int)
	EnableGlobalVar() bool //

	GetSentNet() bool
	SetSentNet(bool)

	SetDstIP(string)
	GetDstIP() string
	SetDstPort(int)
	GetDstPort() int

	SetnsHandle(netns.NsHandle)
	GetnsHandle() netns.NsHandle

	SetContainerPID(uint)
	GetContainerPID() uint

	SetContainerID(string)
	GetContainerID() string

	SetPodName(string)
	GetPodName() []string
}

type eConfig struct {
	Pid           uint64
	Uid           uint64
	PerCpuMapSize int // ebpf map size for per Cpu.   see https://github.com/gojue/CACAPTURE/issues/433 .
	SentNet       bool
	DstIP         string
	DstPort       int
	nsHandle      netns.NsHandle
	ContainerPID  uint
	ContainerID   string
	PodName       []string
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

func (c *eConfig) Check() error {
	return nil
}

func (c *eConfig) GetSentNet() bool {
	return c.SentNet
}

func (c *eConfig) SetSentNet(b bool) {
	c.SentNet = b
}
func (c *eConfig) SetDstIP(ip string) {
	c.DstIP = ip
}
func (c *eConfig) GetDstIP() string {
	return c.DstIP
}
func (c *eConfig) SetDstPort(port int) {
	c.DstPort = port
}
func (c *eConfig) GetDstPort() int {
	return c.DstPort
}
func (c *eConfig) SetnsHandle(nsHandle netns.NsHandle) {
	c.nsHandle = nsHandle
}
func (c *eConfig) GetnsHandle() netns.NsHandle {
	return c.nsHandle
}

func (c *eConfig) SetContainerPID(cid uint) {
	c.ContainerPID = cid
}
func (c *eConfig) GetContainerPID() uint {
	return c.ContainerPID
}
func (c *eConfig) SetContainerID(cid string){
	c.ContainerID= cid
}
func (c *eConfig)GetContainerID()string{
	return c.ContainerID
}

func (c *eConfig) SetPodName(podname string) {
	c.PodName = []string{podname}
}
func (c *eConfig) GetPodName() []string {
	return c.PodName
}
