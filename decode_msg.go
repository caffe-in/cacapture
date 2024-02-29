package main

import (
	"bytes"
	"encoding/binary"
)

type TcSkbEvent struct {
	eventType uint8
	Ts        uint64    `json:"ts"`
	Pid       uint32    `json:"pid"`
	Comm      [16]byte  `json:"Comm"`
	Cmdline   [256]byte `json:"Cmdline"`
	Len       uint32    `json:"len"`
	Ifindex   uint32    `json:"ifindex"`
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
