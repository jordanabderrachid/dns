package dns

import (
	"fmt"
	"strings"
)

// Question represents the question of the DNS message
type Question struct {
	Name  Name
	Type  QType
	Class Class
}

// ToBytes return the bytes array form of the question, to be transmitted over the
// wire
func (q *Question) ToBytes() []byte {
	data := make([]byte, 0, 0)
	data = append(data, q.Name.ToBytes()...)

	data = append(data, byte(q.Type>>8))
	data = append(data, byte(q.Type&0xFF))

	data = append(data, byte(q.Class>>8))
	data = append(data, byte(q.Class&0xFF))

	return data
}

func (q *Question) String() string {
	lines := []string{
		fmt.Sprintf("[name] %s", q.Name.GetName()),
		fmt.Sprintf("[type] %s", q.Type),
		fmt.Sprintf("[class] %s", q.Class),
	}

	return strings.Join(lines, "\n")
}

func questionFromBytes(data []byte) (Question, int, error) {
	name := Name{}
	n, err := name.fromBytes(data)
	if err != nil {
		return Question{}, 0, err
	}

	qtype, err := extractQType(data[n], data[n+1])
	if err != nil {
		return Question{}, 0, err
	}

	class, err := extractClass(data[n+2], data[n+3])
	if err != nil {
		return Question{}, 0, err
	}

	return Question{
		Name:  name,
		Type:  qtype,
		Class: class,
	}, n + 3, nil
}
