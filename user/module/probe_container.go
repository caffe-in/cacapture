package module

import (
	"bytes"
	"cacapture/assets"
	"cacapture/user/config"
	"cacapture/user/event"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

type TlsCaptureModelType uint8

const (
	TlsCaptureModelTypePcap TlsCaptureModelType = iota
	TlsCaptureModelTypeText
	TlsCaptureModelTypeKeylog
)

type MContainerProbe struct {
	Module
	MTCProbe

	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map

	// pid[fd:Addr]
	pidConns map[uint32]map[uint32]string

	keyloggerFilename string
	keylogger         *os.File
	masterKeys        map[string]bool
	eBPFProgramType   TlsCaptureModelType

	sslVersionBpfMap map[string]string // bpf map key: ssl version, value: bpf map key
	sslBpfFile       string            // ssl bpf file
	isBoringSSL      bool              //
	masterHookFunc   string            // SSL_in_init on boringSSL,  SSL_write on openssl
	cgroupPath       string
}

func (m *MContainerProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	m.Module.Init(ctx, logger, conf)
	m.conf = conf
	m.Module.SetChild(m)
	m.eventMaps = make([]*ebpf.Map, 0, 2)
	m.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)
	m.pidConns = make(map[uint32]map[uint32]string)

	var err error

	// var model = m.conf.(*config.ContainerConfig).Model

	var pcapFile = m.conf.(*config.ContainerConfig).PcapFile
	m.eBPFProgramType = TlsCaptureModelTypePcap

	fileInfo, err := filepath.Abs(pcapFile)
	if err != nil {
		return err
	}
	m.pcapngFilename = fileInfo
	var ts unix.Timespec
	err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return err
	}
	startTime := ts.Nano()
	// Calculate the boot time using the monotonic time (since m is the clock we're using as a timestamp)
	// Note: m is NOT the real boot time, as the monotonic clock doesn't take into account system sleeps.
	bootTime := time.Now().UnixNano() - startTime

	m.startTime = uint64(startTime)
	m.bootTime = uint64(bootTime)

	m.tcPackets = make([]*TcPacket, 0, 1024)
	m.tcPacketLocker = &sync.Mutex{}
	m.masterKeyBuffer = bytes.NewBuffer([]byte{})
	return nil

}

func (m *MContainerProbe) Start() error {
	return m.start()
}
func (m *MContainerProbe) start() error {
	var err error

	m.logger.Printf("%s\tPcapng MODEL\n", m.Name())
	err = m.setupManagerPcap()
	if err != nil {
		return err

	}

	var bpfFileName = filepath.Join("user/bytecode", m.sslBpfFile)
	m.logger.Printf("%s\tBPF bytecode filename:%s\n", m.Name(), bpfFileName)
	byteBuf, err := assets.Asset(bpfFileName)

	if err != nil {
		return fmt.Errorf("%s\tcouldn't find asset %v .", m.Name(), err)
	}
	if err = m.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), m.bpfManagerOptions); err != nil {
		return fmt.Errorf("couldn't init manager %v", err)
	}

	// start the bootstrap manager
	if err = m.bpfManager.Start(); err != nil {
		return fmt.Errorf("couldn't start bootstrap manager %v .", err)
	}
	err = m.initDecodeFunPcap()
	if err != nil {
		return err
	}
	return nil
}

func (m *MContainerProbe) constantEditor() []manager.ConstantEditor {
	var editor = []manager.ConstantEditor{
		{
			Name:  "target_pid",
			Value: uint64(m.conf.GetPid()),
			//FailOnMissing: true,
		},
		{
			Name:  "target_uid",
			Value: uint64(m.conf.GetUid()),
		},
		{
			Name:  "target_port",
			Value: uint64(m.conf.(*config.ContainerConfig).Port),
		},
	}

	if m.conf.GetPid() <= 0 {
		m.logger.Printf("%s\ttarget all process. \n", m.Name())
	} else {
		m.logger.Printf("%s\ttarget PID:%d \n", m.Name(), m.conf.GetPid())
	}

	if m.conf.GetUid() <= 0 {
		m.logger.Printf("%s\ttarget all users. \n", m.Name())
	} else {
		m.logger.Printf("%s\ttarget UID:%d \n", m.Name(), m.conf.GetUid())
	}

	return editor
}
func (m *MContainerProbe) AddConn(pid, fd uint32, addr string) {
	if fd <= 0 {
		m.logger.Printf("%s\tAddConn failed. pid:%d, fd:%d, addr:%s\n", m.Name(), pid, fd, addr)
		return
	}
	// save
	var connMap map[uint32]string
	var f bool
	connMap, f = m.pidConns[pid]
	if !f {
		connMap = make(map[uint32]string)
	}
	connMap[fd] = addr
	m.pidConns[pid] = connMap
	//m.logger.Printf("%s\tAddConn pid:%d, fd:%d, addr:%s, mapinfo:%v\n", m.Name(), pid, fd, addr, m.pidConns)
	return
}

func (m *MContainerProbe) Dispatcher(eventStruct event.IEventStruct) {
	// detect eventStruct type
	switch eventStruct.(type) {
	case *event.ConnDataEvent:
		m.AddConn(eventStruct.(*event.ConnDataEvent).Pid, eventStruct.(*event.ConnDataEvent).Fd, eventStruct.(*event.ConnDataEvent).Addr)
	case *event.TcSkbEvent:
		err := m.dumpTcSkb(eventStruct.(*event.TcSkbEvent))
		if err != nil {
			m.logger.Printf("%s\t save packet error %s .\n", m.Name(), err.Error())
		}
		// case *event.SSLDataEvent:
		// 	m.dumpSslData(eventStruct.(*event.SSLDataEvent))
	}
	//m.logger.Println(eventStruct)
}

func (m *MContainerProbe) Close() error {
	if m.eBPFProgramType == TlsCaptureModelTypePcap {
		m.logger.Printf("%s\tsaving pcapng file %s\n", m.Name(), m.pcapngFilename)
		i, err := m.savePcapng()
		if err != nil {
			m.logger.Printf("%s\tsave pcanNP failed, error:%v. \n", m.Name(), err)
		}

		if i == 0 {
			m.logger.Printf("nothing captured, please check your network interface, see \"ecapture tls -h\" for more information.")
		} else {
			m.logger.Printf("%s\t save %d packets into pcapng file.\n", m.Name(), i)
			m.logger.Printf("lost packet num is %d\n", Lost_samples_num)
			m.logger.Printf("lost rate is %f\n", float64(Lost_samples_num)/float64(i+Lost_samples_num))
		}

	}
	m.logger.Printf("%s\tclose. \n", m.Name())
	if err := m.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v .", err)
	}
	return m.Module.Close()
}
func (m *MContainerProbe) Events() []*ebpf.Map {
	return m.eventMaps
}
func (m *MContainerProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := m.eventFuncMaps[em]
	return fun, found
}
func init() {
	mod := &MContainerProbe{}
	mod.name = ModuleNameContainer
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
