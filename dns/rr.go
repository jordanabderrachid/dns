package dns

import (
	"fmt"
)

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
	// AAAAType is the RR type representing a ipv6 host address
	AAAAType Type = 28
	// CAAType is the RR type representing a DNS Certification Authority Authorization
	CAAType Type = 257
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

func extractType(left, right byte) (Type, error) {
	value := uint16(left)<<8 | uint16(right)
	switch value {
	case 1:
		return AType, nil
	case 2:
		return NSType, nil
	case 3:
		return MDType, nil
	case 4:
		return MFType, nil
	case 5:
		return CNAMEType, nil
	case 6:
		return SOAType, nil
	case 7:
		return MBType, nil
	case 8:
		return MGType, nil
	case 9:
		return MRType, nil
	case 10:
		return NULLType, nil
	case 11:
		return WKSType, nil
	case 12:
		return PTRType, nil
	case 13:
		return HINFOType, nil
	case 14:
		return MINFOType, nil
	case 15:
		return MXType, nil
	case 16:
		return TXTType, nil
	case 28:
		return AAAAType, nil
	case 257:
		return CAAType, nil
	default:
		return 0, fmt.Errorf("failed to extract type. invalid value 0x%x", value)
	}
}

func (t Type) String() string {
	return QType(t).String()
}

// QType represents the type of a query. It is a superset of Type. All Type are valid Qtype.
type QType Type

func (t QType) String() string {
	switch t {
	case QType(AType):
		return "A"
	case QType(NSType):
		return "NS"
	case QType(MDType):
		return "MD"
	case QType(MFType):
		return "MF"
	case QType(CNAMEType):
		return "CNAME"
	case QType(SOAType):
		return "SOA"
	case QType(MBType):
		return "MB"
	case QType(MGType):
		return "MG"
	case QType(MRType):
		return "MR"
	case QType(NULLType):
		return "NULL"
	case QType(WKSType):
		return "WKS"
	case QType(PTRType):
		return "PTR"
	case QType(HINFOType):
		return "HINFO"
	case QType(MINFOType):
		return "MINFO"
	case QType(MXType):
		return "MX"
	case QType(TXTType):
		return "TXT"
	case QType(AAAAType):
		return "AAAA"
	case QType(CAAType):
		return "CAA"
	case AXFRQType:
		return "AXFRQ"
	case MAILBQType:
		return "MAILB"
	case MAILAQType:
		return "MAILA"
	case ANYQType:
		return "ANY"
	default:
		return "Unknown"
	}
}

func extractQType(left, right byte) (QType, error) {
	value := uint16(left)<<8 | uint16(right)
	switch value {
	case 252:
		return AXFRQType, nil
	case 253:
		return MAILBQType, nil
	case 254:
		return MAILAQType, nil
	case 255:
		return ANYQType, nil
	default:
		t, err := extractType(left, right)
		return QType(t), err
	}
}

// Class represents the class of the resource record.
type Class uint16

func (c Class) String() string {
	switch c {
	case INClass:
		return "IN"
	case CSClass:
		return "CS"
	case CHClass:
		return "CH"
	case HSClass:
		return "HS"
	case ANYClass:
		return "ANY"
	default:
		return "Unknown"
	}
}

func extractClass(left, right byte) (Class, error) {
	value := uint16(left)<<8 | uint16(right)
	switch value {
	case 1:
		return INClass, nil
	case 2:
		return CSClass, nil
	case 3:
		return CHClass, nil
	case 4:
		return HSClass, nil
	case 255:
		return ANYClass, nil
	default:
		return ANYClass, fmt.Errorf("failed to extract class. invalid value 0x%x", value)
	}
}

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

func (rr ResourceRecord) stringLines() []string {
	return []string{
		fmt.Sprintf("[name] %s", rr.Name.GetName()),
		fmt.Sprintf("[type] %s", rr.Type),
		fmt.Sprintf("[class] %s", rr.Class),
		fmt.Sprintf("[ttl] %d", rr.TTL),
		fmt.Sprintf("[data] %v", rr.Data),
	}
}

func resourceRecordFromBytes(data []byte, offset int) (ResourceRecord, int, error) {
	n := 0
	name := Name{}
	bytesRead, err := name.fromBytes(data, offset)
	if err != nil {
		return ResourceRecord{}, 0, err
	}
	n += bytesRead
	offset += bytesRead

	rtype, err := extractType(data[offset], data[offset+1])
	if err != nil {
		return ResourceRecord{}, 0, err
	}
	n += 2
	offset += 2

	class, err := extractClass(data[offset], data[offset+1])
	if err != nil {
		return ResourceRecord{}, 0, err
	}
	n += 2
	offset += 2

	ttl := int32(data[offset])<<24 | int32(data[offset+1])<<16 | int32(data[offset+2])<<8 | int32(data[offset+3])
	n += 4
	offset += 4

	dataLength := uint16(data[offset])<<8 | uint16(data[offset+1])
	n += 2
	offset += 2

	rdata := data[offset : offset+int(dataLength)]
	n += int(dataLength)

	return ResourceRecord{
		Name:       name,
		Type:       rtype,
		Class:      class,
		TTL:        ttl,
		DataLength: dataLength,
		Data:       rdata,
	}, n, nil
}
