package event

import (
	"bytes"
	"encoding/binary"
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

func (te *TcSkbEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &te.Ts); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &te.Pid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &te.Comm); err != nil {
		return
	}
	//if err = binary.Read(buf, binary.LittleEndian, &te.Cmdline); err != nil {
	//	return
	//}
	//TODO
	te.Cmdline[0] = 91 //ascii 91
	if err = binary.Read(buf, binary.LittleEndian, &te.Len); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &te.Ifindex); err != nil {
		return
	}
	tmpData := make([]byte, te.Len)
	if err = binary.Read(buf, binary.LittleEndian, &tmpData); err != nil {
		return
	}
	te.payload = tmpData
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
