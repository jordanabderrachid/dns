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
