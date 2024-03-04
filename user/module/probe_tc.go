package module

import (
	"bytes"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

type TcPacket struct {
	info gopacket.CaptureInfo //caffe
	data []byte
}
type MTCProbe struct {
	pcapngFilename  string
	ifIdex          int
	ifName          string
	pcapWriter      *pcapgo.NgWriter
	startTime       uint64
	bootTime        uint64
	tcPackets       []*TcPacket
	masterKeyBuffer *bytes.Buffer
	tcPacketLocker  *sync.Mutex
}
