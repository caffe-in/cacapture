package module

import (
	"cacapture/user/config"
	"cacapture/user/event"
	"errors"
	"fmt"
	"math"
	"net"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"
)

func (m *MContainerProbe) setupManagerPcap() error {
	var ifname, binaryPath string

	ifname = m.conf.(*config.ContainerConfig).Ifname
	m.ifName = ifname

	var probes []*manager.Probe

	interf, err := net.InterfaceByName(m.ifName)
	if err != nil {
		return err
	}

	isNetIfaceLo := interf.Flags&net.FlagLoopback == net.FlagLoopback

	skipLoopback := true
	if isNetIfaceLo && skipLoopback {
		return fmt.Errorf("%s\t%s is a loopback interface, skip it", m.Name(), m.ifName)
	}
	m.ifIdex = interf.Index

	probes = append(probes, &manager.Probe{
		Section:          "classifier/egress",
		EbpfFuncName:     "egress_cls_func",
		Ifname:           m.ifName,
		NetworkDirection: manager.Egress,
	})
	probes = append(probes, &manager.Probe{
		Section:          "classifier/ingress",
		EbpfFuncName:     "ingress_cls_func",
		Ifname:           m.ifName,
		NetworkDirection: manager.Ingress,
	})
	binaryPath = m.conf.(*config.ContainerConfig).Openssl
	m.sslBpfFile = "tc.o" // assinged by caffein
	// m.logger.Printf("%s\tHOOK type:%d, binrayPath:%s\n", m.Name(), m.conf.(*config.ContainerConfig).ElfType, binaryPath)
	// m.logger.Printf("%s\tIfname:%s, Ifindex:%d,  Port:%d, Pcapng filepath:%s\n", m.Name(), m.ifName, m.ifIdex, m.conf.(*config.ContainerConfig).Port, m.pcapngFilename)
	// m.logger.Printf("%s\tHook masterKey function:%s\n", m.Name(), m.masterHookFunc)
	netIfs, err := net.Interfaces()
	if err != nil {
		return err
	}

	err = m.createPcapng(netIfs)
	if err != nil {
		return err
	}
	probes = append(probes, &manager.Probe{
		Section:          "uprobe/SSL_write_key",
		EbpfFuncName:     "probe_ssl_master_key",
		AttachToFuncName: m.masterHookFunc, // SSL_do_handshake or SSL_write
		BinaryPath:       binaryPath,
		UID:              "uprobe_ssl_master_key",
	})
	probes = append(probes, &manager.Probe{
		EbpfFuncName:     "tcp_sendmsg",
		Section:          "kprobe/tcp_sendmsg",
		AttachToFuncName: "tcp_sendmsg",
	})
	m.bpfManager = &manager.Manager{
		Probes: probes,

		Maps: []*manager.Map{
			{
				Name: "mastersecret_events",
			},
			{
				Name: "skb_events",
			},
		},
	}

	m.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}

	if m.conf.EnableGlobalVar() {
		// 填充 RewriteContants 对应map
		m.bpfManagerOptions.ConstantEditors = m.constantEditor()
	}
	return nil
}

func (m *MContainerProbe) initDecodeFunPcap() error {
	//SkbEventsMap 与解码函数映射
	SkbEventsMap, found, err := m.bpfManager.GetMap("skb_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:skb_events")
	}
	m.eventMaps = append(m.eventMaps, SkbEventsMap)
	sslEvent := &event.TcSkbEvent{}
	//sslEvent.SetModule(m)
	m.eventFuncMaps[SkbEventsMap] = sslEvent

	MasterkeyEventsMap, found, err := m.bpfManager.GetMap("mastersecret_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:mastersecret_events")
	}
	m.eventMaps = append(m.eventMaps, MasterkeyEventsMap)

	var masterkeyEvent event.IEventStruct

	masterkeyEvent = &event.MasterSecretEvent{}

	//masterkeyEvent.SetModule(m)
	m.eventFuncMaps[MasterkeyEventsMap] = masterkeyEvent
	return nil
}
