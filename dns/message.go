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

// Question represents the question of the DNS message
type Question struct {
	Name  Name
	Type  QType
	Class Class
}

// Message represents the message exchanged during a DNS communication
// A Message can either be a query or a response
type Message struct {
	Header     Header
	Question   Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
}

// NewQuestion builds a basic message that contains a single ANYType ANYClass question
func NewQuestion(name string) (*Message, error) {
	n := Name{}
	if err := n.SetName(name); err != nil {
		return nil, err
	}

	q := Question{
		Name:  n,
		Type:  ANYQType,
		Class: ANYClass,
	}
	h := Header{
		ID:            1,
		Opcode:        QueryOpcode,
		RD:            true,
		RCode:         NoErrorRCode,
		QuestionCount: 1,
	}
	return &Message{
		Header:   h,
		Question: q,
	}, nil
}
