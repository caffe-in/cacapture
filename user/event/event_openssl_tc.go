package event

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	TaskCommLen = 16
	CmdlineLen  = 256
)

type TcSkbEvent struct {
	eventType EventType
	Ts        uint64            `json:"ts"`
	Pid       uint32            `json:"pid"`
	Comm      [TaskCommLen]byte `json:"Comm"`
	Cmdline   [CmdlineLen]byte  `json:"Cmdline"`
	Len       uint32            `json:"len"`
	Ifindex   uint32            `json:"ifindex"`
	payload   []byte
}

func (te *TcSkbEvent) SetPayload(payload []byte) {
	te.payload = payload
}

func (te *TcSkbEvent) Decode(payload []byte) (err error) {
	// buf := bytes.NewBuffer(payload)
	reader := bytes.NewReader(payload)
	// to combine the process, but we don't need these now
	if err = binary.Read(reader, binary.LittleEndian, &te.Ts); err != nil {
		return
	}
	if err = binary.Read(reader, binary.LittleEndian, &te.Pid); err != nil {
		return
	}
	if err = binary.Read(reader, binary.LittleEndian, &te.Comm); err != nil {
		return
	}
	//if err = binary.Read(buf, binary.LittleEndian, &te.Cmdline); err != nil {
	//	return
	//}
	//TODO
	// te.Cmdline[0] = 91 //ascii 91
	// offset := int64(8 + 4 + TaskCommLen)
	// if _, err := reader.Seek(offset, io.SeekStart); err != nil {
	// 	return err
	// }
	if err = binary.Read(reader, binary.LittleEndian, &te.Len); err != nil {
		return
	}
	// if err = binary.Read(reader, binary.LittleEndian, &te.Ifindex); err != nil {
	// 	return
	// }

	if int(reader.Len()) < int(te.Len) {
		return errors.New("payload is too short to contain the expected data")
	}
	// 直接引用 payload 数据，避免拷贝
	pos := len(payload) - reader.Len()

	// 直接引用 payload 数据，避免拷贝
	te.payload = payload[pos : pos+int(te.Len)]

	return nil
}

func (te *TcSkbEvent) StringHex() string {
	// b := dumpByteSlice(te.payload, COLORGREEN)
	// b.WriteString(COLORRESET)
	// s := fmt.Sprintf("Pid:%d, Comm:%s, Length:%d, Ifindex:%d, Payload:%s", te.Pid, te.Comm, te.Len, te.Ifindex, b.String())
	// return s
	return ""
}

func (te *TcSkbEvent) String() string {

	s := fmt.Sprintf("Pid:%d, Comm:%s, Length:%d, Ifindex:%d, Payload:[internal data]", te.Pid, te.Comm, te.Len, te.Ifindex)
	return s
}

func (te *TcSkbEvent) Clone() IEventStruct {
	event := new(TcSkbEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (te *TcSkbEvent) EventType() EventType {
	return te.eventType
}

func (te *TcSkbEvent) GetUUID() string {
	return fmt.Sprintf("%d-%d-%s", te.Pid, te.Ifindex, te.Comm)
}

func (te *TcSkbEvent) Payload() []byte {
	return te.payload
}

func (te *TcSkbEvent) PayloadLen() int {
	return int(te.Len)
}
