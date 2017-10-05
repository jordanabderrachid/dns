package dns

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
