package dns

import (
	"fmt"
	"strings"
)

const (
	QueryOpcode  Opcode = 0
	IQueryOpcode Opcode = 1
	StatusOpcode Opcode = 2
)

const (
	NoErrorRCode        RCode = 0
	FormatErrorRCode    RCode = 1
	ServerFailureRCode  RCode = 2
	NameErrorRCode      RCode = 3
	NotImplementedRCode RCode = 4
	RefusedRCode        RCode = 5
)

// QR is a flag specifing if the message is a query(0) or a response(1)
type QR bool

// AA stands for Authoritative Answer. This bit specifies that the responding name
// server is an authority for the domain name in question section
type AA bool

// TC stands for TrunCation. This bit specifies wether the message has been truncated
type TC bool

// RD stands for Recursion Desired. If this bit is set, it directs the name server to
// pursue the query recursively
type RD bool

// RA stands for Recursion Available. It denotes the recursive query is supported by the
// server
type RA bool

// RCode is the response code
type RCode uint8

func (r RCode) String() string {
	switch r {
	case NoErrorRCode:
		return "No Error Rcode"
	case FormatErrorRCode:
		return "Fornat Error Rcode"
	case ServerFailureRCode:
		return "Server Failure Rcode"
	case NameErrorRCode:
		return "Name Error Rcode"
	case NotImplementedRCode:
		return "Not Implemented Rcode"
	case RefusedRCode:
		return "Refused Rcode"
	default:
		return "Unknown Rcode"
	}
}

// Opcode specify the kind of query the message is
type Opcode uint8

func (o Opcode) String() string {
	switch o {
	case QueryOpcode:
		return "Query Opcode"
	case IQueryOpcode:
		return "IQuery Opcode"
	case StatusOpcode:
		return "Status Opcode"
	default:
		return "Unkown Opcode"
	}
}

// Header represents the header of the DNS message
type Header struct {
	ID              uint16
	QR              QR
	Opcode          Opcode
	AA              AA
	TC              TC
	RD              RD
	RA              RA
	RCode           RCode
	QuestionCount   uint16
	AnswerCount     uint16
	AuthorityCount  uint16
	AdditionalCount uint16
}

func (h *Header) String() string {
	lines := []string{
		fmt.Sprintf("[id] %d", h.ID),
		fmt.Sprintf("[qr] %v", h.QR),
		fmt.Sprintf("[opcode] %s", h.Opcode),
		fmt.Sprintf("[aa] %v", h.AA),
		fmt.Sprintf("[tc] %v", h.TC),
		fmt.Sprintf("[rd] %v", h.RD),
		fmt.Sprintf("[ra] %v", h.RA),
		fmt.Sprintf("[rcode] %s", h.RCode),
		fmt.Sprintf("[question count] %d", h.QuestionCount),
		fmt.Sprintf("[answer count] %d", h.AnswerCount),
		fmt.Sprintf("[authority count] %d", h.AuthorityCount),
		fmt.Sprintf("[additional count] %d", h.AdditionalCount),
	}

	return strings.Join(lines, "\n")
}

// ToBytes returns the byte array form of the header, to be transmitted over the wire
func (h *Header) ToBytes() []byte {
	data := make([]byte, 0, 0)

	data = append(data, byte(h.ID>>8))
	data = append(data, byte(h.ID&0xFF))

	byteQR := boolToByte(bool(h.QR)) << 7
	byteOpcode := (byte(h.Opcode) & 0xFF) << 3
	byteAA := boolToByte(bool(h.AA)) << 2
	byteTC := boolToByte(bool(h.TC)) << 1
	byteRD := boolToByte(bool(h.RD))
	data = append(data, byteQR|byteOpcode|byteAA|byteTC|byteRD)

	byteRA := boolToByte(bool(h.RA)) << 7
	byteRCode := byte(h.RCode & 0xFF)
	data = append(data, byteRA|byteRCode)

	data = append(data, byte(h.QuestionCount>>8))
	data = append(data, byte(h.QuestionCount&0xFF))

	data = append(data, byte(h.AnswerCount>>8))
	data = append(data, byte(h.AnswerCount&0xFF))

	data = append(data, byte(h.AuthorityCount>>8))
	data = append(data, byte(h.AuthorityCount&0xFF))

	data = append(data, byte(h.AdditionalCount>>8))
	data = append(data, byte(h.AdditionalCount&0xFF))

	return data
}

func boolToByte(b bool) byte {
	if b {
		return 1
	}

	return 0
}

func headerFromBytes(data []byte) (Header, error) {
	if len(data) < 12 {
		return Header{}, fmt.Errorf("failed to parse header, invalid data length. length=%d", len(data))
	}

	id := catBytes(data[0], data[1])
	qr := extractQR(data[2])
	opcode, err := extractOpcode(data[2])
	if err != nil {
		return Header{}, err
	}
	aa := extractAA(data[2])
	tc := extractTC(data[2])
	rd := extractRD(data[2])
	ra := extractRA(data[3])
	rcode, err := extractRCode(data[3])
	if err != nil {
		return Header{}, err
	}
	questionCount := catBytes(data[4], data[5])
	answerCount := catBytes(data[6], data[7])
	authorityCount := catBytes(data[8], data[9])
	additionalCount := catBytes(data[10], data[11])

	return Header{
		ID:              id,
		QR:              qr,
		Opcode:          opcode,
		AA:              aa,
		TC:              tc,
		RD:              rd,
		RA:              ra,
		RCode:           rcode,
		QuestionCount:   questionCount,
		AnswerCount:     answerCount,
		AuthorityCount:  authorityCount,
		AdditionalCount: additionalCount,
	}, nil
}

func catBytes(left, right byte) uint16 {
	return uint16(left)<<8 | uint16(right)
}

func extractQR(data byte) QR {
	if (data&128)>>7 == 1 { // & 0x10000000
		return true
	}

	return false
}

func extractOpcode(data byte) (Opcode, error) {
	switch (data >> 3) & 15 { // & 0b00001111
	case 0:
		return QueryOpcode, nil
	case 1:
		return IQueryOpcode, nil
	case 2:
		return StatusOpcode, nil
	default:
		return QueryOpcode, fmt.Errorf("failed to parse opcode, unknown value 0x%x", data)
	}
}

func extractAA(data byte) AA {
	if (data&4)>>2 == 1 { // & 0b00000100
		return true
	}

	return false
}

func extractTC(data byte) TC {
	if (data&2)>>1 == 1 { // & 0b00000010
		return true
	}

	return false
}

func extractRD(data byte) RD { // & 0b00000001
	if data&1 == 1 {
		return true
	}

	return false
}

func extractRA(data byte) RA {
	if (data&128)>>7 == 1 { // & 0b10000000
		return true
	}

	return false
}

func extractRCode(data byte) (RCode, error) {
	switch data & 15 { // & 0b00001111
	case 0:
		return NoErrorRCode, nil
	case 1:
		return FormatErrorRCode, nil
	case 2:
		return ServerFailureRCode, nil
	case 3:
		return NameErrorRCode, nil
	case 4:
		return NotImplementedRCode, nil
	case 5:
		return RefusedRCode, nil
	default:
		return NoErrorRCode, fmt.Errorf("failed to parse rcode, unknown value 0x%x", data)
	}
}
