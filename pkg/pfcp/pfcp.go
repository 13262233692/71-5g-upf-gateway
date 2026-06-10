package pfcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	Port = 8805

	HeaderLen = 12

	MsgTypeAssociationSetupRequest  = 5
	MsgTypeAssociationSetupResponse = 6
	MsgTypeSessionEstablishmentReq  = 50
	MsgTypeSessionEstablishmentRes  = 51
	MsgTypeSessionModificationReq   = 52
	MsgTypeSessionModificationRes   = 53
	MsgTypeSessionDeletionReq       = 54
	MsgTypeSessionDeletionRes       = 55
	MsgTypeSessionReportReq         = 56
	MsgTypeSessionReportRes         = 57

	IETypeCreatePDR       = 1
	IETypePDI             = 2
	IETypeCreateFAR       = 3
	IETypeCreateQER       = 4
	IETypeQFI             = 5
	IETypeTEID            = 21
	IETypeGBR             = 24
	IETypeMBR             = 25
	IETypeApplyAction     = 44
	IETypePDRID           = 56
	IETypeFARID           = 108
	IETypeQERID           = 109
	IETypeUEIPAddress     = 93
	IETypeFTEID           = 21
	IETypeSourceInterface = 20
	IETypeNetworkInstance = 22

	SourceInterfaceAccess     = 0
	SourceInterfaceCore       = 1
	SourceInterfaceSGiLAN6    = 2
	SourceInterfaceCPFunction = 3

	ActionDrop  = 0x01
	ActionForward = 0x02
	ActionBuffer  = 0x04
	ActionNotify  = 0x08
)

type Header struct {
	Version       uint8
	MPFlag        bool
	SFlag         bool
	MessageType   uint8
	MessageLength uint16
	SEID          uint64
	Sequence      uint32
}

type IE struct {
	Type   uint16
	Length uint16
	Value  []byte
}

type Message struct {
	Header Header
	IEs    []IE
}

type PDRInfo struct {
	PDRID          uint16
	Precedence     uint32
	PDIInterface   uint8
	TEID           uint32
	QFI            uint8
	NetworkInstance string
}

type FARInfo struct {
	FARID       uint32
	Action      uint8
	DstInterface uint8
}

type QERInfo struct {
	QERID   uint32
	QFI     uint8
	GBRUL   uint64
	GBRDL   uint64
	MBRUL   uint64
	MBRDL   uint64
}

type SessionMod struct {
	SEID  uint64
	PDRs  []PDRInfo
	FARs  []FARInfo
	QERs  []QERInfo
}

func ParseHeader(data []byte) (*Header, int, error) {
	if len(data) < 4 {
		return nil, 0, errors.New("pfcp: header too short")
	}

	h := &Header{}
	h.Version = (data[0] >> 5) & 0x07
	h.MPFlag = (data[0] & 0x10) != 0
	h.SFlag = (data[0] & 0x08) != 0
	h.MessageType = data[1]
	h.MessageLength = binary.BigEndian.Uint16(data[2:4])

	offset := 4

	if h.SFlag {
		if len(data) < offset+8 {
			return nil, 0, errors.New("pfcp: SEID truncated")
		}
		h.SEID = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	if len(data) < offset+4 {
		return nil, 0, errors.New("pfcp: sequence truncated")
	}
	h.Sequence = binary.BigEndian.Uint32(data[offset : offset+4]) >> 8
	offset += 4

	return h, offset, nil
}

func ParseMessage(data []byte) (*Message, error) {
	hdr, offset, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}

	msg := &Message{Header: *hdr}

	remaining := data[offset:]
	for len(remaining) >= 4 {
		ieType := binary.BigEndian.Uint16(remaining[0:2])
		ieLen := binary.BigEndian.Uint16(remaining[2:4])

		if len(remaining) < int(ieLen)+4 {
			break
		}

		ie := IE{
			Type:   ieType,
			Length: ieLen,
			Value:  remaining[4 : 4+ieLen],
		}
		msg.IEs = append(msg.IEs, ie)
		remaining = remaining[4+ieLen:]
	}

	return msg, nil
}

func ParseSessionModification(msg *Message) (*SessionMod, error) {
	mod := &SessionMod{
		SEID: msg.Header.SEID,
	}

	for _, ie := range msg.IEs {
		switch ie.Type {
		case IETypeCreatePDR:
			pdr := parseCreatePDR(ie.Value)
			mod.PDRs = append(mod.PDRs, pdr)
		case IETypeCreateFAR:
			far := parseCreateFAR(ie.Value)
			mod.FARs = append(mod.FARs, far)
		case IETypeCreateQER:
			qer := parseCreateQER(ie.Value)
			mod.QERs = append(mod.QERs, qer)
		}
	}

	return mod, nil
}

func parseCreatePDR(data []byte) PDRInfo {
	pdr := PDRInfo{}
	remaining := data

	for len(remaining) >= 4 {
		ieType := binary.BigEndian.Uint16(remaining[0:2])
		ieLen := binary.BigEndian.Uint16(remaining[2:4])
		if len(remaining) < int(ieLen)+4 {
			break
		}
		ieValue := remaining[4 : 4+ieLen]

		switch ieType {
		case IETypePDRID:
			if len(ieValue) >= 2 {
				pdr.PDRID = binary.BigEndian.Uint16(ieValue[0:2])
			}
		case IETypePDI:
			pdr.PDIInterface, pdr.TEID, pdr.QFI, pdr.NetworkInstance = parsePDI(ieValue)
		}

		remaining = remaining[4+ieLen:]
	}

	return pdr
}

func parsePDI(data []byte) (uint8, uint32, uint8, string) {
	var iface uint8
	var teid uint32
	var qfi uint8
	var ni string
	remaining := data

	for len(remaining) >= 4 {
		ieType := binary.BigEndian.Uint16(remaining[0:2])
		ieLen := binary.BigEndian.Uint16(remaining[2:4])
		if len(remaining) < int(ieLen)+4 {
			break
		}
		ieValue := remaining[4 : 4+ieLen]

		switch ieType {
		case IETypeSourceInterface:
			if len(ieValue) >= 1 {
				iface = ieValue[0] & 0x0F
			}
		case IETypeFTEID:
			if len(ieValue) >= 7 {
				teid = binary.BigEndian.Uint32(ieValue[3:7])
			}
		case IETypeQFI:
			if len(ieValue) >= 1 {
				qfi = ieValue[0] & 0x3F
			}
		case IETypeNetworkInstance:
			ni = string(ieValue)
		}

		remaining = remaining[4+ieLen:]
	}

	return iface, teid, qfi, ni
}

func parseCreateFAR(data []byte) FARInfo {
	far := FARInfo{}
	remaining := data

	for len(remaining) >= 4 {
		ieType := binary.BigEndian.Uint16(remaining[0:2])
		ieLen := binary.BigEndian.Uint16(remaining[2:4])
		if len(remaining) < int(ieLen)+4 {
			break
		}
		ieValue := remaining[4 : 4+ieLen]

		switch ieType {
		case IETypeFARID:
			if len(ieValue) >= 4 {
				far.FARID = binary.BigEndian.Uint32(ieValue[0:4])
			}
		case IETypeApplyAction:
			if len(ieValue) >= 1 {
				far.Action = ieValue[0]
			}
		}

		remaining = remaining[4+ieLen:]
	}

	return far
}

func parseCreateQER(data []byte) QERInfo {
	qer := QERInfo{}
	remaining := data

	for len(remaining) >= 4 {
		ieType := binary.BigEndian.Uint16(remaining[0:2])
		ieLen := binary.BigEndian.Uint16(remaining[2:4])
		if len(remaining) < int(ieLen)+4 {
			break
		}
		ieValue := remaining[4 : 4+ieLen]

		switch ieType {
		case IETypeQERID:
			if len(ieValue) >= 4 {
				qer.QERID = binary.BigEndian.Uint32(ieValue[0:4])
			}
		case IETypeQFI:
			if len(ieValue) >= 1 {
				qer.QFI = ieValue[0] & 0x3F
			}
		case IETypeGBR:
			if len(ieValue) >= 16 {
				qer.GBRUL = binary.BigEndian.Uint64(ieValue[0:8])
				qer.GBRDL = binary.BigEndian.Uint64(ieValue[8:16])
			}
		case IETypeMBR:
			if len(ieValue) >= 16 {
				qer.MBRUL = binary.BigEndian.Uint64(ieValue[0:8])
				qer.MBRDL = binary.BigEndian.Uint64(ieValue[8:16])
			}
		}

		remaining = remaining[4+ieLen:]
	}

	return qer
}

func (q *QERInfo) String() string {
	return fmt.Sprintf("QER{ID=%d, QFI=%d, GBR_UL=%d, GBR_DL=%d, MBR_UL=%d, MBR_DL=%d}",
		q.QERID, q.QFI, q.GBRUL, q.GBRDL, q.MBRUL, q.MBRDL)
}

func BuildAssociationSetupResponse(seid uint64, seq uint32, cause uint8) []byte {
	hdr := make([]byte, 16)
	hdr[0] = 0x28
	hdr[1] = MsgTypeAssociationSetupResponse
	binary.BigEndian.PutUint16(hdr[2:4], 8+4)
	binary.BigEndian.PutUint64(hdr[4:12], seid)
	binary.BigEndian.PutUint32(hdr[12:16], seq<<8)
	hdr[16-1] = cause
	return hdr
}

func BuildSessionEstablishmentResponse(seid uint64, seq uint32, cause uint8) []byte {
	buf := make([]byte, 20)
	buf[0] = 0x38
	buf[1] = MsgTypeSessionEstablishmentRes
	binary.BigEndian.PutUint16(buf[2:4], 8+8)
	binary.BigEndian.PutUint64(buf[4:12], seid)
	binary.BigEndian.PutUint32(buf[12:16], seq<<8)
	buf[16] = 0x00
	buf[17] = 19
	buf[18] = 0x00
	buf[19] = 0x01
	return buf
}

func IPToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}
