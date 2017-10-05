package dns_test

import "testing"
import "github.com/jordanabderrachid/dns/dns"
import "bytes"

func TestQuestionToBytes(t *testing.T) {
	n := dns.Name{}
	n.SetName("foo")

	var cases = []struct {
		q        dns.Question
		expected []byte
	}{
		{
			dns.Question{Name: n},
			[]byte{3, 102, 111, 111, 0, 0, 0, 0, 0},
		},
		{
			dns.Question{Name: n, Type: dns.ANYQType, Class: dns.ANYClass},
			[]byte{3, 102, 111, 111, 0, 0, 255, 0, 255},
		},
	}

	for _, c := range cases {
		actual := c.q.ToBytes()

		if bytes.Compare(actual, c.expected) != 0 {
			t.Fatalf("Question ToBytes returned unexpected output. actual=%v expected=%v question=%v",
				actual, c.expected, c.q)
		}
	}
}
