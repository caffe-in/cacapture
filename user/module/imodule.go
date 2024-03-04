package module

import (
	"cacapture/user/config"
	"cacapture/user/event"
	"context"
	"log"

	"github.com/cilium/ebpf"
)

type IModule interface {
	// Init 初始化
	Init(context.Context, *log.Logger, config.IConfig) error

	// Name 获取当前module的名字
	Name() string

	// Run 事件监听感知
	Run() error

	// Start 启动模块
	Start() error

	// Stop 停止模块
	Stop() error

	// Close 关闭退出
	Close() error

	SetChild(module IModule)

	Decode(*ebpf.Map, []byte) (event.IEventStruct, error)

	Events() []*ebpf.Map

	DecodeFun(p *ebpf.Map) (event.IEventStruct, bool)

	Dispatcher(event.IEventStruct)
}

type Module struct {
	opts *ebpf.CollectionOptions
	// reader []IClose
	ctx    context.Context
	logger *log.Logger
	child  IModule
	// probe的名字
	name string

	// module的类型，uprobe,kprobe等
	mType string

	conf config.IConfig
}

func (m *Module) Init(ctx context.Context, logger *log.Logger, conf config.IConfig) {
	m.ctx = ctx
	m.logger = logger
}
func (m *Module) SetChild(module IModule) {
	m.child = module
}
