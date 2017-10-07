package dns

const (
	// AType is the RR type representing a host address
	AType Type = 1
	// NSType is the RR type representing an authoritative name server
	NSType Type = 2
	// MDType is the RR type representing a mail destination (obsolote, use MX)
	MDType Type = 3
	// MFType is the RR type representing a mail forwarder (obsolote, use MX)
	MFType Type = 4
	// CNAMEType is the RR type representing a canonical name for an alias
	CNAMEType Type = 5
	// SOAType is the RR type representing the start of a zone of authority
	SOAType Type = 6
	// MBType is the RR type representing a mailbox domain name (experimental)
	MBType Type = 7
	// MGType is the RR type representing a mail group member (experimental)
	MGType Type = 8
	// MRType is the RR type representing a mail rename domain name (experimental)
	MRType Type = 9
	// NULLType is the RR type representing a null RR (experimental)
	NULLType Type = 10
	// WKSType is the RR type representing a well known service description
	WKSType Type = 11
	// PTRType is the RR type representing a domain name pointer
	PTRType Type = 12
	// HINFOType is the RR type representing a host information
	HINFOType Type = 13
	// MINFOType is the RR type representing a mailbox or mail list information
	MINFOType Type = 14
	// MXType is the RR type representing a mail exchange
	MXType Type = 15
	// TXTType is the RR type representing text strings
	TXTType Type = 16
)

const (
	// AXFRQType is the query type requesting a transfer of an entire zone
	AXFRQType QType = 252
	// MAILBQType is the query type requesting for mailbox-related records (MB, MG or MR)
	MAILBQType QType = 253
	// MAILAQType is the query type requesting for mail agent RR (obsolete, use MX)
	MAILAQType QType = 254
	// ANYQType is the query type requesting all records
	ANYQType QType = 255
)

const (
	// INClass is the class representing the Internet
	INClass Class = 1
	// CSClass is the class representing the CSNET (obsolete)
	CSClass Class = 2
	// CHClass is the class representing the CHAOS
	CHClass Class = 3
	// HSClass is the class representing the Hesiod
	HSClass Class = 4
	// ANYClass is the class representing any class
	ANYClass Class = 255
)

// Type represents the type of the resource record.
type Type uint16

// QType represents the type of a query. It is a superset of Type. All Type are valid Qtype.
type QType Type

// Class represents the class of the resource record.
type Class uint16

// ResourceRecord represents a DNS resource record
type ResourceRecord struct {
	Name       Name
	Type       Type
	Class      Class
	TTL        int32
	DataLength uint16
	Data       []byte
}

// ToBytes returns the byte array form of the resource record to be transmitted
// over the wire
func (rr *ResourceRecord) ToBytes() []byte {
	data := make([]byte, 0, 0)

	data = append(data, rr.Name.ToBytes()...)

	data = append(data, byte(rr.Type>>8))
	data = append(data, byte(rr.Type&0xFF))

	data = append(data, byte(rr.Class>>8))
	data = append(data, byte(rr.Class&0xFF))

	data = append(data, byte(rr.TTL>>24))
	data = append(data, byte(rr.TTL>>16))
	data = append(data, byte(rr.TTL>>8))
	data = append(data, byte(rr.TTL&0xFF))

	data = append(data, byte(rr.DataLength>>8))
	data = append(data, byte(rr.DataLength&0xFF))

	data = append(data, rr.Data...)

	return data
}
