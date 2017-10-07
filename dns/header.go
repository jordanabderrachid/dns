package dns

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

// Opcode specify the kind of query the message is
type Opcode uint8

// Header represents the header of the DNS message
type Header struct {
	ID              int16
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
