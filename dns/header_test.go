package dns_test

import "testing"
import "github.com/jordanabderrachid/dns/dns"
import "bytes"

func TestHeaderToBytes(t *testing.T) {
	var cases = []struct {
		h        dns.Header
		expected []byte
	}{
		{
			dns.Header{
				ID:            256,
				QR:            false,
				Opcode:        dns.StatusOpcode,
				AA:            false,
				TC:            false,
				RD:            true,
				RA:            false,
				RCode:         dns.NoErrorRCode,
				QuestionCount: 1,
			},
			[]byte{1, 0, 17, 0, 0, 1, 0, 0, 0, 0, 0, 0},
		},
	}

	for _, c := range cases {
		actual := c.h.ToBytes()

		if bytes.Compare(actual, c.expected) != 0 {
			t.Fatalf("Header ToBytes returned unexpected output. actual=%v expected=%v header=%v",
				actual, c.expected, c.h)
		}
	}
}
