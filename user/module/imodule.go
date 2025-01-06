package module

import (
	"cacapture/user/config"
	"cacapture/user/event"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

// var dstAddr = &net.UDPAddr{
// 	IP:   net.ParseIP("172.16.8.64").To4(),
// 	Port: 4789,
// }

// var conn, _ = net.DialUDP("udp", nil, dstAddr)

var Lost_samples_num = 0

const numWorkers = 0

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
	opts   *ebpf.CollectionOptions
	reader []IClose
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

func (m *Module) Run() error {
	m.logger.Printf("Module.Run()")
	//  start
	err := m.child.Start()
	if err != nil {
		return err
	}

	go func() {
		m.run()
	}()

	// go func() {
	// 	m.processor.Serve()
	// }()

	// some panic here
	// go func() {
	// 	m.child.(*MContainerProbe).InitUPDConn()
	// }()

	err = m.readEvents()
	if err != nil {
		return err
	}

	return nil
}

func (m *Module) run() {
	for {
		select {
		case _ = <-m.ctx.Done():
			err := m.child.Stop()
			if err != nil {
				m.logger.Fatalf("%s\t stop Module error:%v.", m.child.Name(), err)
			}
			return
		}
	}
}
func (m *Module) Name() string {
	return m.name
}
func (m *Module) readEvents() error {
	var errChan = make(chan error, 8)
	go func() {
		for {
			select {
			case err := <-errChan:
				m.logger.Printf("%s\treadEvents error:%v", m.child.Name(), err)
			}
		}
	}()

	for _, e := range m.child.Events() {
		switch {
		case e.Type() == ebpf.PerfEventArray:
			m.perfEventReader(errChan, e)
		case e.Type() == ebpf.RingBuf:
			m.ringbufEventReader(errChan, e)
		default:
			return fmt.Errorf("%s\tunsupported mapType:%s , mapinfo:%s",
				m.child.Name(), e.Type().String(), e.String())
		}
	}

	return nil
}

func (m *Module) perfEventReader(errChan chan error, em *ebpf.Map) {
	// m.logger.Printf("%s\tperfEventReader created. mapSize:%d MB", m.child.Name(), m.conf.GetPerCpuMapSize()/1024/1024)
	rd, err := perf.NewReader(em, m.conf.GetPerCpuMapSize())
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	m.reader = append(m.reader, rd)

	go func() {
		// m.child.(*MContainerProbe).InitUPDConn()
		for {
			//判断ctx是不是结束
			select {
			case _ = <-m.ctx.Done():
				m.logger.Printf("%s\tperfEventReader received close signal from context.Done().", m.child.Name())
				return
			default:
			}
			record, err := rd.Read()
			// PacketCount++
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}

				errChan <- fmt.Errorf("%s\treading from perf event reader: %s", m.child.Name(), err)
				return
			}

			if record.LostSamples != 0 {
				Lost_samples_num += int(record.LostSamples)
				m.logger.Printf("%s\tperf event ring buffer full, dropped %d samples", m.child.Name(), record.LostSamples)
				continue
			}
			if m.conf.GetSentNet() {
				PacketCount++
				rawSampleSize := binary.LittleEndian.Uint32(record.RawSample[28:32])
				vxlanHeader := VXLANHeader{
					Flags: 0x8,
				}
				vxlanHeader.VNI[0] = byte((VNI_NUM >> 16) & 0xFF) // 获取VNI的高8位
				vxlanHeader.VNI[1] = byte((VNI_NUM >> 8) & 0xFF)  // 获取VNI的中间8位
				vxlanHeader.VNI[2] = byte(VNI_NUM & 0xFF)         // 获取VNI的低8位

				buffer := vxlanBufferPool.Get().([]byte)
				actualBuffer := buffer[:VXLANHeaderSize+rawSampleSize]
				actualBuffer[0] = 0x08 // Flags字段，设置VXLAN头的标志位，其中0x08表示VNI存在
				// 接下来的3个字节 (_ [3]byte) 默认为0，不需要操作

				// 设置VNI字段
				actualBuffer[4] = byte((VNI_NUM >> 16) & 0xFF) // VNI的高8位
				actualBuffer[5] = byte((VNI_NUM >> 8) & 0xFF)  // VNI的中间8位
				actualBuffer[6] = byte(VNI_NUM & 0xFF)         // VNI的低8位

				copy(actualBuffer[VXLANHeaderSize:], record.RawSample[36:36+rawSampleSize])
				ethernetFrame := actualBuffer
				_, err := m.child.(*MContainerProbe).UDP_conn.Write(ethernetFrame)
				vxlanBufferPool.Put(buffer)
				if err != nil {
					log.Println("Write to UDP failed: ", err, "the size of packetBytes is: ", len(ethernetFrame))

					return
				}
			} else {
				var e event.IEventStruct
				e, err = m.child.Decode(em, record.RawSample)
				if err != nil {
					m.logger.Printf("%s\tm.child.decode error:%v", m.child.Name(), err)
					continue
				}
				m.Dispatcher(e)

			}

		}

	}()
}

func (m *Module) ringbufEventReader(errChan chan error, em *ebpf.Map) {
	rd, err := ringbuf.NewReader(em)
	if err != nil {
		errChan <- fmt.Errorf("%s\tcreating %s reader dns: %s", m.child.Name(), em.String(), err)
		return
	}
	m.reader = append(m.reader, rd)
	go func() {
		for {
			//判断ctx是不是结束
			select {
			case _ = <-m.ctx.Done():
				m.logger.Printf("%s\tringbufEventReader received close signal from context.Done().", m.child.Name())
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					m.logger.Printf("%s\tReceived signal, exiting..", m.child.Name())
					return
				}
				errChan <- fmt.Errorf("%s\treading from ringbuf reader: %s", m.child.Name(), err)
				return
			}

			var e event.IEventStruct
			e, err = m.child.Decode(em, record.RawSample)
			if err != nil {
				m.logger.Printf("%s\tm.child.decode error:%v", m.child.Name(), err)
				continue
			}

			// 上报数据
			m.Dispatcher(e)
		}
	}()
}
func (m *Module) Dispatcher(e event.IEventStruct) {
	switch e.EventType() {
	case event.EventTypeOutput:
		m.logger.Println(e.String())

	case event.EventTypeModuleData:
		// Save to cache
		m.child.Dispatcher(e)
	default:
		m.logger.Printf("%s\tunknown event type:%d", m.child.Name(), e.EventType())
	}
}
func (m *Module) Close() error {
	m.logger.Printf("%s\tclose", m.child.Name())
	for _, iClose := range m.reader {
		if err := iClose.Close(); err != nil {
			return err
		}
	}
	return nil
}
func (m *Module) DecodeFun(p *ebpf.Map) (event.IEventStruct, bool) {
	panic("Module.DecodeFun() not implemented yet")
}
func (m *Module) Decode(em *ebpf.Map, b []byte) (event event.IEventStruct, err error) {

	es, found := m.child.DecodeFun(em)
	if !found {
		err = fmt.Errorf("%s\tcan't found decode function :%s, address:%p", m.child.Name(), em.String(), em)
		return
	}

	te := es.Clone()
	err = te.Decode(b)
	if err != nil {
		return nil, err
	}
	return te, nil
}
func (m *Module) Events() []*ebpf.Map {
	panic("Module.Events() not implemented yet")
}
func (m *Module) Stop() error {
	return nil
}
