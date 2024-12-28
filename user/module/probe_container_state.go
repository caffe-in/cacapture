package module

import (
	"bytes"
	"cacapture/assets"
	"cacapture/user/config"
	"cacapture/user/container"
	"cacapture/user/event"
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"path/filepath"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

type MContainerStateProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]event.IEventStruct
	eventMaps         []*ebpf.Map
	eBPFProgramType   TlsCaptureModelType
	sslBpfFile        string // ssl bpf file

	csm *container.ContainerStateManager
}

func (m *MContainerStateProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	m.Module.Init(ctx, logger, conf)
	m.Module.SetChild(m)

	// just syscall probe
	m.eventMaps = make([]*ebpf.Map, 0, 1)
	m.eventFuncMaps = make(map[*ebpf.Map]event.IEventStruct)

	m.eBPFProgramType = TlsCaptureModelTypePcap
	m.csm = container.NewContainerStateManager()
	m.csm.InitContainerStates()
	m.csm.StartPodInformer(ctx, logger)
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Println("Starting Prometheus metrics server on :8081")
		if err := http.ListenAndServe(":8081", nil); err != nil {
			log.Fatalf("Failed to start metrics server: %v", err)
		}
	}()
	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done(): // 当 ctx 被取消时，优雅退出 Goroutine
				log.Println("MonitorContainersWithLLM stopped")
				return
			default:
				m.csm.MonitorContainersWithLLM() // 执行定时任务
			}
		}
	}(ctx)

	return nil
}

func (m *MContainerStateProbe) Start() error {
	return m.start()
}
func (m *MContainerStateProbe) start() error {
	var err error

	m.logger.Printf("%s\tModule Start\n", m.Name())
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

func (m *MContainerStateProbe) setupManagerPcap() error {
	var probes []*manager.Probe
	syscallEnterProbe := &manager.Probe{
		Section:      "tracepoint/raw_syscalls/sys_enter",
		EbpfFuncName: "sys_enter",
	}
	probes = append(probes, syscallEnterProbe)
	m.bpfManager = &manager.Manager{
		Probes: probes,

		Maps: []*manager.Map{
			{
				Name: "syscall_events",
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

	m.sslBpfFile = "container_states.o" // assinged by caffein
	return nil
}

func (m *MContainerStateProbe) initDecodeFunPcap() error {

	//SyscallEventsMap 与解码函数映射
	SyscallEventsMap, found, err := m.bpfManager.GetMap("syscall_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:syscall_events")
	}
	m.eventMaps = append(m.eventMaps, SyscallEventsMap)
	syscallEvent := &event.SyscallEvent{}
	m.eventFuncMaps[SyscallEventsMap] = syscallEvent

	return nil
}

func (m *MContainerStateProbe) Dispatcher(e event.IEventStruct) {
	if ecs, ok := e.(event.ContainerStatusIEventStruct); ok {
		pid := ecs.GetPid()
		state, ok := m.csm.GetContainerStateByPID(pid)
		if !ok {
			// m.logger.Printf("pid:%d not found in container state map", pid)
		} else {
			// m.logger.Printf("pid:%d found in container state map", pid)
			newState := ecs.UpdateContainerState(state)
			m.csm.UpdateContainerState(pid, newState)
		}

	} else {
		m.logger.Println("not ContainerStatusIEventStruct")
	}
}
func (m *MContainerStateProbe) Events() []*ebpf.Map {
	return m.eventMaps
}
func (m *MContainerStateProbe) DecodeFun(em *ebpf.Map) (event.IEventStruct, bool) {
	fun, found := m.eventFuncMaps[em]
	return fun, found
}

func init() {
	mod := &MContainerStateProbe{}
	mod.name = ModuleNameContainerState
	mod.mType = ProbeTypeTP
	Register(mod)
}
