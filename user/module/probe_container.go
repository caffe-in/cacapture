package module

import (
	"cacapture/user/config"
	"cacapture/user/event"
	"context"
	"log"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
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
}

func (m *MContainerProbe) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) error {
	m.Module.Init(ctx, logger, conf)
	m.conf = conf
	m.Module.SetChild(m)
}
