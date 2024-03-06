package event

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	Ssl3RandomSize     = 32
	MasterSecretMaxLen = 48
	EvpMaxMdSize       = 64
)

type TlsVersion struct {
	Version int32
}

type MasterSecretEvent struct {
	eventType EventType
	Version   int32 `json:"version"` // TLS Version

	// TLS 1.2 or older
	ClientRandom [Ssl3RandomSize]byte     `json:"clientRandom"` // Client Random
	MasterKey    [MasterSecretMaxLen]byte `json:"masterKey"`    // Master Key

	// TLS 1.3
	CipherId               uint32             `json:"cipherId"`               // Cipher ID
	HandshakeSecret        [EvpMaxMdSize]byte `json:"handshakeSecret"`        // Handshake Secret
	HandshakeTrafficHash   [EvpMaxMdSize]byte `json:"handshakeTrafficHash"`   // Handshake Traffic Hash
	ClientAppTrafficSecret [EvpMaxMdSize]byte `json:"clientAppTrafficSecret"` // Client App Traffic Secret
	ServerAppTrafficSecret [EvpMaxMdSize]byte `json:"serverAppTrafficSecret"` // Server App Traffic Secret
	ExporterMasterSecret   [EvpMaxMdSize]byte `json:"exporterMasterSecret"`   // Exporter Master Secret
	payload                string
}

func (me *MasterSecretEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &me.Version); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.ClientRandom); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.MasterKey); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.CipherId); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.HandshakeSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.HandshakeTrafficHash); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.ClientAppTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.ServerAppTrafficSecret); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &me.ExporterMasterSecret); err != nil {
		return
	}
	me.payload = fmt.Sprintf("CLIENT_RANDOM %02x %02x", me.ClientRandom, me.MasterKey)
	return nil
}

func (me *MasterSecretEvent) StringHex() string {
	v := TlsVersion{
		Version: me.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), me.ClientRandom)
	return s
}

func (me *MasterSecretEvent) String() string {
	v := TlsVersion{
		Version: me.Version,
	}
	s := fmt.Sprintf("TLS Version:%s, ClientRandom:%02x", v.String(), me.ClientRandom)
	return s
}

func (me *MasterSecretEvent) Clone() IEventStruct {
	event := new(MasterSecretEvent)
	event.eventType = EventTypeModuleData
	return event
}

func (me *MasterSecretEvent) EventType() EventType {
	return me.eventType
}

func (me *MasterSecretEvent) GetUUID() string {
	return fmt.Sprintf("%02X", me.ClientRandom)
}

func (me *MasterSecretEvent) Payload() []byte {
	return []byte(me.payload)
}

func (me *MasterSecretEvent) PayloadLen() int {
	return len(me.payload)
}
