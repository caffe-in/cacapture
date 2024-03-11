package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const MaxDataSize = 1024 * 4
const SaDataLen = 14

const (
	Ssl2Version   = 0x0002
	Ssl3Version   = 0x0300
	Tls1Version   = 0x0301
	Tls11Version  = 0x0302
	Tls12Version  = 0x0303
	Tls13Version  = 0x0304
	Dtls1Version  = 0xFEFF
	Dtls12Version = 0xFEFD
)

type TlsVersion struct {
	Version int32
}

func (t TlsVersion) String() string {
	switch t.Version {
	case Ssl2Version:
		return "SSL2_VERSION"
	case Ssl3Version:
		return "SSL3_VERSION"
	case Tls1Version:
		return "TLS1_VERSION"
	case Tls11Version:
		return "TLS1_1_VERSION"
	case Tls12Version:
		return "TLS1_2_VERSION"
	case Tls13Version:
		return "TLS1_3_VERSION"
	case Dtls1Version:
		return "DTLS1_VERSION"
	case Dtls12Version:
		return "DTLS1_2_VERSION"
	}
	return fmt.Sprintf("TLS_VERSION_UNKNOW_%d", t.Version)
}

type ConnDataEvent struct {
	eventType   EventType
	TimestampNs uint64          `json:"timestampNs"`
	Pid         uint32          `json:"pid"`
	Tid         uint32          `json:"tid"`
	Fd          uint32          `json:"fd"`
	SaData      [SaDataLen]byte `json:"saData"`
	Comm        [16]byte        `json:"Comm"`
	Addr        string          `json:"addr"`
}

func (ce *ConnDataEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ce.TimestampNs); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Tid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Fd); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.SaData); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ce.Comm); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(ce.SaData[0:2])
	ip := net.IPv4(ce.SaData[2], ce.SaData[3], ce.SaData[4], ce.SaData[5])
	ce.Addr = fmt.Sprintf("%s:%d", ip, port)
	return nil
}

func (ce *ConnDataEvent) StringHex() string {
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Addr: %s", ce.Pid, bytes.TrimSpace(ce.Comm[:]), ce.Tid, ce.Fd, ce.Addr)
	return s
}

func (ce *ConnDataEvent) String() string {
	s := fmt.Sprintf("PID:%d, Comm:%s, TID:%d, FD:%d, Addr: %s", ce.Pid, bytes.TrimSpace(ce.Comm[:]), ce.Tid, ce.Fd, ce.Addr)
	return s
}

func (ce *ConnDataEvent) Clone() IEventStruct {
	event := new(ConnDataEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (ce *ConnDataEvent) EventType() EventType {
	return ce.eventType
}

func (ce *ConnDataEvent) GetUUID() string {
	return fmt.Sprintf("%d_%d_%s_%d", ce.Pid, ce.Tid, bytes.TrimSpace(ce.Comm[:]), ce.Fd)
}

func (ce *ConnDataEvent) Payload() []byte {
	return []byte(ce.Addr)
}

func (ce *ConnDataEvent) PayloadLen() int {
	return len(ce.Addr)
}
