package module

import (
	"bytes"
	"cacapture/assets"
	"cacapture/user/config"
	"cacapture/user/container"
	"cacapture/user/event"
	"context"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"
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
const SEND_NET = true

type MContainerProbe struct {
	Module
	MTCProbe

	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
	eBPFProgramType   TlsCaptureModelType
	sslBpfFile        string // ssl bpf file

	UDP_conn *net.UDPConn
	csm      *container.ContainerStateManager
}

func (m *MContainerProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	m.Module.Init(ctx, logger, conf)
	m.conf = conf
	m.Module.SetChild(m)
	m.eventMaps = make([]*ebpf.Map, 0, 2)
	m.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)

	var err error

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

	m.InitUPDConn()

	return nil

}

func (m *MContainerProbe) Start() error {
	return m.start()
}
func (m *MContainerProbe) start() error {
	var err error

	// start the udp conn

	m.logger.Printf("%s\tPcapng MODEL\n", m.Name())
	err = m.setupManagerPcap()
	if err != nil {
		m.logger.Println("set up fail")
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

func (m *MContainerProbe) Dispatcher(eventStruct event.IEventStruct) {

	err := m.dumpTcSkb(eventStruct.(*event.TcSkbEvent))
	if err != nil {
		m.logger.Printf("%s\t save packet error %s .\n", m.Name(), err.Error())
	}

}

func (m *MContainerProbe) Close() error {
	if m.eBPFProgramType == TlsCaptureModelTypePcap {
		m.logger.Printf("%s\tsaving pcapng file %s\n", m.Name(), m.pcapngFilename)
		m.tcPacketLocker.Lock()
		defer m.tcPacketLocker.Unlock()
		sort.Slice(m.tcPackets, func(i, j int) bool {
			return m.tcPackets[i].info.Timestamp.Before(m.tcPackets[j].info.Timestamp)
		})
		i, err := m.savePcapng()

		if err != nil {
			m.logger.Printf("%s\tsave pcanNP failed, error:%v. \n", m.Name(), err)
		}
		PacketCount += i
		if PacketCount == 0 {
			m.logger.Printf("nothing captured, please check your network interface, see \"CACAPTURE tls -h\" for more information.")
		} else {

			m.logger.Printf("%s\t save %d packets into pcapng file.\n", m.Name(), PacketCount)
			m.logger.Printf("lost packet num is %d\n", Lost_samples_num)
			m.logger.Printf("lost rate is %f\n", float64(Lost_samples_num)/float64(PacketCount+Lost_samples_num))
		}

	}
	m.logger.Printf("%s\tclose. \n", m.Name())
	if err := m.bpfManager.Stop(manager.CleanAll); err != nil {
		return fmt.Errorf("couldn't stop manager %v .", err)
	}
	m.CloseUPDConn()
	return m.Module.Close()
}
func (m *MContainerProbe) Events() []*ebpf.Map {
	return m.eventMaps
}
func (m *MContainerProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := m.eventFuncMaps[em]
	return fun, found
}
func (m *MContainerProbe) InitUPDConn() error {
	dstAddr := &net.UDPAddr{
		IP:   net.ParseIP(m.conf.GetDstIP()).To4(),
		Port: m.conf.GetDstPort(),
	}

	conn, err := net.DialUDP("udp", nil, dstAddr)
	if err != nil {
		fmt.Println("DialUDP failed: ", err)
		return err
	}
	m.UDP_conn = conn
	return nil
}
func (m *MContainerProbe) CloseUPDConn() {
	m.UDP_conn.Close()
}
func init() {
	mod := &MContainerProbe{}
	mod.name = ModuleNameContainer
	mod.mType = ProbeTypeUprobe
	Register(mod)
}
