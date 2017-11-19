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
		"",
		"[anwers]",
	}

	lines = append(lines, m.answersToString()...)

	return strings.Join(lines, "\n")
}

func (m Message) answersToString() []string {
	lines := make([]string, 0)

	for _, a := range m.Answers {
		lines = append(lines, "[answer]")
		lines = append(lines, a.stringLines()...)
		lines = append(lines, "")
	}

	return lines
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
func MessageFromBytes(data []byte) (Message, int, error) {
	n := 0
	header, bytesRead, err := headerFromBytes(data)
	if err != nil {
		return Message{}, n, err
	}
	n += bytesRead

	question, bytesRead, err := questionFromBytes(data, n)
	if err != nil {
		return Message{}, n, err
	}
	n += bytesRead

	answers := make([]ResourceRecord, header.AnswerCount)
	for i := 0; i < int(header.AnswerCount); i++ {
		rr, bytesRead, err := resourceRecordFromBytes(data, n)
		if err != nil {
			return Message{}, n, err
		}

		answers[i] = rr
		n += bytesRead
	}

	return Message{
		Header:   header,
		Question: question,
		Answers:  answers,
	}, n, nil
}
