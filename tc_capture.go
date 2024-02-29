package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

var tc_package_num int = 0

func create_mtc_probe() *MTCProbe {
	var ts unix.Timespec
	m := &MTCProbe{}
	startTime := ts.Nano()
	bootTime := time.Now().UnixNano() - startTime

	m.startTime = uint64(startTime)
	m.bootTime = uint64(bootTime)

	m.tcPackets = make([]*TcPacket, 0, 1024)
	m.tcPacketLocker = &sync.Mutex{}
	m.masterKeyBuffer = bytes.NewBuffer([]byte{})
	return m
}
func capture_tc_packet(wg *sync.WaitGroup, map_id uint32, ctx context.Context, logger *log.Logger, m *MTCProbe) {
	var errChan = make(chan error, 8)
	targetMap, err := ebpf.NewMapFromID(ebpf.MapID(map_id))
	if err != nil {
		log.Fatalf("Failed to get map from ID: %v", err)
	}
	rd, err := perf.NewReader(targetMap, 1024*os.Getpagesize())
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", targetMap.String(), err)
		return
	}
	go func() {

		for {
			//判断ctx是不是结束

			select {
			case _ = <-ctx.Done():
				logger.Printf("ctrl c caffein")
				logger.Printf("perfEventReader received close signal from context.Done().")
				return
			default:
			}
			record, err := rd.Read()
			tc_package_num++
			logger.Println("capture one packet")
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				errChan <- fmt.Errorf("reading from perf event reader: %s", err)
				return
			}

			if record.LostSamples != 0 {
				logger.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			// 解码数据
			te := &TcSkbEvent{}
			if err := te.Decode(record.RawSample); err != nil {
				logger.Printf("Failed to decode perf event: %v", err)
			}
			err = m.dumpTcSkb(te)
			if err != nil {
				logger.Printf("save packet error")
			}
		}
	}()
}

func main() {
	// 初始化日志记录器
	logger := log.New(os.Stdout, "logger: ", log.LstdFlags)

	// 创建一个带有取消功能的上下文
	ctx, cancel := context.WithCancel(context.TODO())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	var wg sync.WaitGroup
	wg.Add(1)
	containerID := "a79ba701f8b0"
	ifname := "eth0"
	bpfFileName := "kern/tc.o"
	networkMapID, skbeventMapID, err := AttachEbpfMap(containerID, ifname, bpfFileName)
	if err != nil {
		logger.Printf("Failed to attach eBPF map: %v", err)
	}
	logger.Printf("networkMapID: %d, skbeventMapID: %d", networkMapID, skbeventMapID)

	netIfs, err := net.Interfaces()
	if err != nil {
		logger.Printf("Failed to get network interfaces: %v", err)
	}
	// 创建MTCProbe对象,并初始化，创建pcapng文件，准备写入
	m := create_mtc_probe()
	m.createPcapng(netIfs)
	capture_tc_packet(&wg, skbeventMapID, ctx, logger, m)

	// 等待信号
	<-c
	cancel()

	// 保存pcapng文件
	logger.Printf("the num of tc package is %d", tc_package_num)
	_, err = m.savePcapng()
	if err != nil {
		logger.Printf("Failed to save pcapng file: %v", err)
	}
	wg.Done()

	wg.Wait()
	os.Exit(0)

}
