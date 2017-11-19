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

func (n *Name) fromBytes(data []byte) (int, error) {
	name := ""

	i := 0
	for {
		name += "."
		labelLength := int(data[i])

		if labelLength == 0 {
			i++
			break
		}

		label := string(data[i+1 : i+1+labelLength])
		name += label
		i += labelLength + 1
	}

	n.name = name
	n.data = data[0:i]
	return i, nil
}

func nameFromBytes(data []byte) (Name, int, error) {
	return Name{}, 0, nil
}
