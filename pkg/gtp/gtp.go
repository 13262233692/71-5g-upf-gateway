package gtp

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	GTPuPort    = 2152
	GTPv1       = 1
	GTPProtocol = 1

	GTPHeaderLen      = 8
	GTPMessageTypeTPPDU = 0xFF

	FlagVersion    = 0xE0
	FlagProtocol   = 0x10
	FlagExtHeader  = 0x04
	FlagSequence   = 0x02
	FlagPN         = 0x01

	ExtHeaderTypePDUSession = 0x85
)

type Header struct {
	Flags        uint8
	MessageType  uint8
	Length       uint16
	TEID         uint32
	SequenceNum  uint16
	NPduNum      uint8
	NextExtType  uint8
	ExtHeaders   []ExtHeader
}

type ExtHeader struct {
	Type   uint8
	Length uint8
	Value  []byte
}

type Message struct {
	Header    Header
	Payload   []byte
}

func ParseHeader(data []byte) (*Header, int, error) {
	if len(data) < GTPHeaderLen {
		return nil, 0, errors.New("gtp: packet too short")
	}

	h := &Header{
		Flags:       data[0],
		MessageType: data[1],
		Length:      binary.BigEndian.Uint16(data[2:4]),
		TEID:        binary.BigEndian.Uint32(data[4:8]),
	}

	version := (h.Flags & FlagVersion) >> 5
	if version != GTPv1 {
		return nil, 0, errors.New("gtp: unsupported version")
	}

	if (h.Flags & FlagProtocol) != (GTPProtocol << 4) {
		return nil, 0, errors.New("gtp: invalid protocol type")
	}

	offset := GTPHeaderLen

	if h.Flags&(FlagSequence|FlagPN|FlagExtHeader) != 0 {
		if len(data) < offset+4 {
			return nil, 0, errors.New("gtp: optional fields truncated")
		}
		h.SequenceNum = binary.BigEndian.Uint16(data[offset : offset+2])
		h.NPduNum = data[offset+2]
		h.NextExtType = data[offset+3]
		offset += 4
	}

	if h.Flags&FlagExtHeader != 0 {
		for h.NextExtType != 0 {
			if len(data) < offset+2 {
				return nil, 0, errors.New("gtp: extension header truncated")
			}

			extLen := int(data[offset]) * 4
			extType := data[offset+1]

			if extLen == 0 {
				break
			}

			if len(data) < offset+extLen {
				return nil, 0, errors.New("gtp: extension header value truncated")
			}

			extHdr := ExtHeader{
				Type:   extType,
				Length: uint8(extLen),
				Value:  make([]byte, extLen-2),
			}
			copy(extHdr.Value, data[offset+2:offset+extLen])
			h.ExtHeaders = append(h.ExtHeaders, extHdr)

			h.NextExtType = data[offset+extLen-1]
			offset += extLen
		}
	}

	return h, offset, nil
}

func ParseMessage(data []byte) (*Message, error) {
	hdr, offset, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}

	msg := &Message{
		Header:  *hdr,
		Payload: data[offset:],
	}

	return msg, nil
}

func (h *Header) HeaderLen() int {
	length := GTPHeaderLen
	if h.Flags&(FlagSequence|FlagPN|FlagExtHeader) != 0 {
		length += 4
	}
	for _, ext := range h.ExtHeaders {
		length += int(ext.Length)
	}
	return length
}

func (h *Header) GetQFI() (uint8, bool) {
	for _, ext := range h.ExtHeaders {
		if ext.Type == ExtHeaderTypePDUSession && len(ext.Value) >= 1 {
			return ext.Value[0] & 0x3F, true
		}
	}
	return 0, false
}

func IsGTPuPacket(udpSrc, udpDst uint16) bool {
	return udpSrc == GTPuPort || udpDst == GTPuPort
}

func ParseInnerIP(data []byte) (net.IP, net.IP, uint8, error) {
	if len(data) < 20 {
		return nil, nil, 0, errors.New("ip: packet too short")
	}

	version := (data[0] & 0xF0) >> 4
	if version != 4 {
		return nil, nil, 0, errors.New("ip: only IPv4 supported")
	}

	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl {
		return nil, nil, 0, errors.New("ip: invalid header length")
	}

	protocol := data[9]
	srcIP := net.IP(data[12:16])
	dstIP := net.IP(data[16:20])

	return srcIP, dstIP, protocol, nil
}
