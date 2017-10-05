package dns_test

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/jordanabderrachid/dns/dns"
)

func TestSetName_emptyName(t *testing.T) {
	n := dns.Name{}
	err := n.SetName("")
	if err == nil {
		t.Fatal("SetName should return an error if name is an empty string")
	}

	if !strings.Contains(err.Error(), "domain name cannot be empty") {
		t.Error("SetName should return a specific error if name is an empty string")
	}
}

func TestSetName_nameTooLarge(t *testing.T) {
	rawString := make([]byte, 256, 256)
	for i := 0; i <= 255; i++ {
		rawString[i] = 0x80
	}

	name := string(rawString)
	n := dns.Name{}
	err := n.SetName(name)
	if err == nil {
		t.Fatal("SetName should return an error if name is larger than 255 bytes")
	}

	if !strings.Contains(err.Error(), "domain name cannot exceed 255 bytes") {
		t.Fatal("SetName should return a specific error if name is larger than 255 btyes")
	}
}

func TestSetName_labelTooLarge(t *testing.T) {
	rawLabel := make([]byte, 64, 64)
	for i := 0; i <= 63; i++ {
		rawLabel[i] = 0x80
	}
	label := string(rawLabel)

	n := dns.Name{}
	err := n.SetName(fmt.Sprintf("bar.%s.foo", label))
	if err == nil {
		t.Fatal("SetName should return an error if label is larger than 63 bytes")
	}

	if !strings.Contains(err.Error(), "domain name label cannot exceed 63 bytes") {
		t.Fatal("SetName should return a specific error if label is larger than 63 bytes")
	}
}

func TestSetName_emptyLabel(t *testing.T) {
	var names = []string{
		".foo",
		".foo.",
		"..foo",
		"..foo.",
		"foo..bar",
		"foo..bar.",
		"foo..",
	}

	n := dns.Name{}
	for _, name := range names {
		err := n.SetName(name)
		if err == nil {
			t.Fatalf("SetName should return an error if label is empty. name=%s", name)
		}

		if !strings.Contains(err.Error(), "domain name label cannot be empty") {
			t.Fatalf("SetName should return a specific error if label is empty. name=%s", name)
		}
	}
}

func TestSetName(t *testing.T) {
	var cases = []struct {
		name     string // input
		expected []byte // expected result
	}{
		{"foo.bar", []byte{3, 102, 111, 111, 3, 98, 97, 114, 0}},
		{"foo.bar.", []byte{3, 102, 111, 111, 3, 98, 97, 114, 0}},
	}

	n := dns.Name{}
	for _, c := range cases {
		if err := n.SetName(c.name); err != nil {
			log.Fatalf("SetName failed for name %s with error %s", c.name, err.Error())
		}

		actual := n.ToBytes()
		if bytes.Compare(actual, c.expected) != 0 {
			log.Fatalf("SetName produced incorrect result. actual=%v, expected=%v, name=%s",
				actual, c.expected, c.name)
		}
	}
}
