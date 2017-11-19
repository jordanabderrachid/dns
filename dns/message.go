package dns

import (
	"strings"
)

// Message represents the message exchanged during a DNS communication
// A Message can either be a query or a response
type Message struct {
	Header     Header
	Question   Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
}

func (m Message) String() string {
	lines := []string{
		"[message]",
		"",
		"[header]",
		m.Header.String(),
		"",
		"[question]",
		m.Question.String(),
	}

	return strings.Join(lines, "\n")
}

// ToBytes returns the byte array form of the message to be transmitted over
// the wire
func (m *Message) ToBytes() []byte {
	data := make([]byte, 0, 0)

	data = append(data, m.Header.ToBytes()...)
	data = append(data, m.Question.ToBytes()...)

	for _, answer := range m.Answers {
		data = append(data, answer.ToBytes()...)
	}

	for _, authority := range m.Authority {
		data = append(data, authority.ToBytes()...)
	}

	for _, additional := range m.Additional {
		data = append(data, additional.ToBytes()...)
	}

	return data
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
		Class: INClass,
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

// MessageFromBytes .
func MessageFromBytes(data []byte) (Message, error) {
	header, err := headerFromBytes(data)
	if err != nil {
		return Message{}, err
	}

	offset := 12 // header is 12 bytes long
	question, n, err := questionFromBytes(data[offset:])
	if err != nil {
		return Message{}, err
	}
	offset += n

	return Message{
		Header:   header,
		Question: question,
	}, nil
}
