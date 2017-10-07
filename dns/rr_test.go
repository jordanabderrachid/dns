package dns_test

import "testing"
import "github.com/jordanabderrachid/dns/dns"
import "bytes"

func TestResourceRecordToBytes(t *testing.T) {
	name := dns.Name{}
	name.SetName("foo.bar")
	var cases = []struct {
		rr       dns.ResourceRecord
		expected []byte
	}{
		{
			dns.ResourceRecord{
				Name:       name,
				Type:       dns.TXTType,
				Class:      dns.ANYClass,
				TTL:        100000000,
				DataLength: 1000,
				Data:       []byte{0, 1, 2, 3},
			},
			[]byte{3, 102, 111, 111, 3, 98, 97, 114, 0, 0, 16, 0, 255, 5, 245, 225, 0, 3, 232, 0, 1, 2, 3},
		},
	}

	for _, c := range cases {
		actual := c.rr.ToBytes()

		if bytes.Compare(actual, c.expected) != 0 {
			t.Fatalf("ResourceRecord ToBytes return unexpected result. actual=%v, expected=%v, rr=%v",
				actual, c.expected, c.rr)
		}
	}
}
