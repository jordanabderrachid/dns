package dns

import (
	"fmt"
	"strings"
)

const labelLengthMask byte = 0x3F // 0b00111111

// Name is the name of the owner of the resource record. ie: "www.google.com."
// Must be at most 255 bytes long.
type Name struct {
	name string
	data []byte
}

// SetName set the name
func (n *Name) SetName(name string) error {
	if name == "" {
		return fmt.Errorf("domain name cannot be empty")
	}

	if len([]byte(name)) > 255 {
		return fmt.Errorf("domain name cannot exceed 255 bytes. %s", name)
	}

	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)
	labels := strings.Split(name, ".")
	if len(labels) == 0 {
		labels = append(labels, "")
	}

	data := make([]byte, 0, 0)
	for _, label := range labels {
		rawLabel := []byte(label)
		if len(rawLabel) == 0 {
			return fmt.Errorf("domain name label cannot be empty. %s", label)
		}

		if len(rawLabel) > 63 {
			return fmt.Errorf("domain name label cannot exceed 63 bytes. %s %s",
				label, name)
		}

		length := byte(len(rawLabel)) & labelLengthMask
		data = append(data, length)
		data = append(data, rawLabel...)
	}

	data = append(data, 0)

	n.data = data
	n.name = name
	return nil
}

// GetName get the name
func (n *Name) GetName() string {
	return n.name
}

// ToBytes return the byte array raw data of the Name
func (n *Name) ToBytes() []byte {
	return n.data
}

func (n *Name) fromBytes(data []byte, offset int) (int, error) {
	name := ""
	i := 0

	for {
		name += "."
		labelLengthByte := data[offset]
		i++
		offset++

		if labelLengthByte == 0 {
			break
		}

		if isPointer(labelLengthByte) {
			left := int(labelLengthByte & 63) // & 0b00111111
			right := int(data[offset])
			i++
			offset++

			location := left<<8 | right
			pointedLabelLength := int(data[location])
			// FIXME: read the entire name, not only first label
			name += string(data[location+1 : location+1+pointedLabelLength])
			break
		}

		labelLength := int(labelLengthByte)
		label := string(data[offset : offset+labelLength])
		name += label
		offset += labelLength
		i += labelLength
	}

	n.name = name
	n.data = data[offset : offset+i]
	return i, nil
}

func isPointer(labelLength byte) bool {
	return labelLength>>6 == 3 // 0b11XXXXXX
}
