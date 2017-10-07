package dns

// Message represents the message exchanged during a DNS communication
// A Message can either be a query or a response
type Message struct {
	Header     Header
	Question   Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
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
