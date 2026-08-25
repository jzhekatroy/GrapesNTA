package main

import "encoding/binary"

// NetFlow v9 / IANA IPFIX information element IDs we decode into FlowRow.
const (
	nfIN_BYTES                     = 1
	nfIN_PKTS                      = 2
	nfPROTOCOL                     = 4
	nfSRC_TOS                      = 5
	nfTCP_FLAGS                    = 6
	nfL4_SRC_PORT                  = 7
	nfIPV4_SRC_ADDR                = 8
	nfSRC_MASK                     = 9
	nfINPUT_SNMP                   = 10
	nfL4_DST_PORT                  = 11
	nfIPV4_DST_ADDR                = 12
	nfDST_MASK                     = 13
	nfOUTPUT_SNMP                  = 14
	nfIPV4_NEXT_HOP                = 15
	nfSRC_AS                       = 16
	nfDST_AS                       = 17
	nfLAST_SWITCHED                = 21
	nfFIRST_SWITCHED               = 22
	nfIPV6_SRC_ADDR                = 27
	nfIPV6_DST_ADDR                = 28
	nfICMP_TYPE                    = 32
	nfSAMPLING_INTERVAL            = 34
	nfSAMPLING_ALGORITHM           = 35
	nfMIN_TTL                      = 52
	nfIN_SRC_MAC                   = 56
	nfOUT_DST_MAC                  = 57
	nfSRC_VLAN                     = 58
	nfDST_VLAN                     = 59
	nfIP_PROTOCOL_VERSION          = 60
	nfIPV6_NEXT_HOP                = 62
	nfIN_DST_MAC                   = 80
	nfOUT_SRC_MAC                  = 81
	nfFLOW_SAMPLER_ID              = 48
	nfFLOW_SAMPLER_MODE            = 49
	nfFLOW_SAMPLER_RANDOM_INTERVAL = 50
)

const (
	nfVersion           = 9
	nfHeaderLen         = 20
	nfTemplateFlowset   = 0
	nfOptionsFlowset    = 1
	nfMinDataTemplateID = 256
	nfMaxTemplateFields = 128
	nfTimeSkewLimit     = 3600 // seconds; fall back to receive time beyond this
)

func readNFUint(b []byte) uint64 {
	switch len(b) {
	case 0:
		return 0
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.BigEndian.Uint16(b))
	case 3:
		return uint64(b[0])<<16 | uint64(b[1])<<8 | uint64(b[2])
	case 4:
		return uint64(binary.BigEndian.Uint32(b))
	case 8:
		return binary.BigEndian.Uint64(b)
	default:
		if len(b) > 8 {
			b = b[len(b)-8:]
		}
		var v uint64
		for _, x := range b {
			v = v<<8 | uint64(x)
		}
		return v
	}
}

func copyIPv4(dst *[16]byte, b []byte) bool {
	if len(b) < 4 {
		return false
	}
	copy(dst[:4], b[:4])
	return true
}

func copyIPv6(dst *[16]byte, b []byte) bool {
	if len(b) < 16 {
		return false
	}
	copy(dst[:], b[:16])
	return true
}

func copyMAC(dst *[6]byte, b []byte) bool {
	if len(b) < 6 {
		return false
	}
	copy(dst[:], b[:6])
	return true
}
