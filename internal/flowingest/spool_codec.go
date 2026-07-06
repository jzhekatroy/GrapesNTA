package flowingest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

// spoolZeroTimeSentinel marks a zero time.Time on the wire. A real timestamp's
// UnixNano is always well above math.MinInt64, so this value can never collide
// with a legitimate instant, and it lets us round-trip the Go zero time exactly
// (its raw UnixNano is outside the invertible range).
const spoolZeroTimeSentinel = math.MinInt64

// Binary spool codec (frame versions 2 and 3).
//
// Rationale: the previous payload encoding used encoding/gob, whose per-call
// reflection and internal buffer/type-descriptor allocations were the dominant
// source of garbage in the collector hot path (visible as runtime.gcDrain /
// gob.* in CPU profiles). This hand-rolled codec writes a flat, self-describing
// byte stream with no reflection and a pooled scratch buffer, which removes that
// allocation churn while keeping the exact FlowRow field set.
//
// Wire layout (little-endian):
//
//	uvarint  rowCount
//	repeated rowCount times, in FlowRow field order:
//	  int64    Date              (unix nanoseconds)
//	  int64    TimeInsertedNs    (unix nanoseconds)
//	  int64    TimeReceivedNs    (unix nanoseconds)
//	  int64    TimeFlowStartNs   (unix nanoseconds)
//	  uvarint  SequenceNum
//	  uvarint  SamplingRate
//	  [16]byte SamplerAddress
//	  string   SourceID
//	  [16]byte SrcAddr
//	  [16]byte DstAddr
//	  uvarint  SrcAS, DstAS, SrcASN, DstASN
//	  string   Direction, SrcKind, DstKind, SrcLabel, DstLabel,
//	           SrcOperator, DstOperator,
//	           SrcAttachmentKind, DstAttachmentKind,
//	           SrcAttachmentBoundary, DstAttachmentBoundary,
//	           SrcAttachmentLabel, DstAttachmentLabel,
//	           SrcAttachmentOperator, DstAttachmentOperator,
//	           SrcEndpointScope, DstEndpointScope,
//	           SrcEndpointSource, DstEndpointSource,
//	           SrcNetworkName, DstNetworkName,
//	           SrcNetworkRole, DstNetworkRole,
//	           SrcRole, DstRole, SrcEntity, DstEntity
//	  uvarint  SrcVLAN, DstVLAN
//	  uvarint  Etype, Proto, SrcPort, DstPort
//	  uvarint  Bytes, Packets
//	  [6]byte  SrcMAC, DstMAC                 -- frame version 3 and 4
//	  uvarint  InIf, OutIf                    -- frame version 4 only
//	  byte     TCPFlags, IPTTL, IPTos         -- frame version 4 only
//
// A "string" is uvarint length followed by raw UTF-8 bytes.
//
// Versioning: extra fields are appended at the tail of each row so a lower
// version record is an exact prefix of a higher one. decodeFlowRowsBinaryVersion
// reads the MAC pair only when hasMAC is set (frame version 3+) and the sFlow
// metadata (InIf/OutIf/TCPFlags/IPTTL/IPTos) only when hasMeta is set (frame
// version 4). Legacy version-2/3 frames still on disk during a rolling restart
// decode unchanged (missing fields stay zero). Frame version 1 (gob) is decoded
// via decodeFramePayload. New frames are always written as version 4. See
// spool.go version dispatch.

// spoolMaxFrameRows caps decode-side allocation from a single (possibly torn or
// hostile) frame. The writer chunks at maxFrameRows (default 50k); this bound is
// generously above any legitimate value while still preventing a bad length
// prefix from forcing a huge allocation before the CRC/format checks catch it.
const spoolMaxFrameRows = 20_000_000

var spoolEncBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func encodeFlowRowsBinary(rows []FlowRow) ([]byte, error) {
	buf := spoolEncBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer spoolEncBufPool.Put(buf)

	var vtmp [binary.MaxVarintLen64]byte
	putUvarint := func(x uint64) {
		n := binary.PutUvarint(vtmp[:], x)
		buf.Write(vtmp[:n])
	}
	putI64 := func(v int64) {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(v))
		buf.Write(b[:])
	}
	putTime := func(t time.Time) {
		if t.IsZero() {
			putI64(spoolZeroTimeSentinel)
			return
		}
		putI64(t.UnixNano())
	}
	putStr := func(s string) {
		putUvarint(uint64(len(s)))
		buf.WriteString(s)
	}

	putUvarint(uint64(len(rows)))
	for i := range rows {
		r := &rows[i]
		putTime(r.Date)
		putTime(r.TimeInsertedNs)
		putTime(r.TimeReceivedNs)
		putTime(r.TimeFlowStartNs)
		putUvarint(uint64(r.SequenceNum))
		putUvarint(r.SamplingRate)
		buf.Write(r.SamplerAddress[:])
		putStr(r.SourceID)
		buf.Write(r.SrcAddr[:])
		buf.Write(r.DstAddr[:])
		putUvarint(uint64(r.SrcAS))
		putUvarint(uint64(r.DstAS))
		putUvarint(uint64(r.SrcASN))
		putUvarint(uint64(r.DstASN))
		putStr(r.Direction)
		putStr(r.SrcKind)
		putStr(r.DstKind)
		putStr(r.SrcLabel)
		putStr(r.DstLabel)
		putStr(r.SrcOperator)
		putStr(r.DstOperator)
		putStr(r.SrcAttachmentKind)
		putStr(r.DstAttachmentKind)
		putStr(r.SrcAttachmentBoundary)
		putStr(r.DstAttachmentBoundary)
		putStr(r.SrcAttachmentLabel)
		putStr(r.DstAttachmentLabel)
		putStr(r.SrcAttachmentOperator)
		putStr(r.DstAttachmentOperator)
		putStr(r.SrcEndpointScope)
		putStr(r.DstEndpointScope)
		putStr(r.SrcEndpointSource)
		putStr(r.DstEndpointSource)
		putStr(r.SrcNetworkName)
		putStr(r.DstNetworkName)
		putStr(r.SrcNetworkRole)
		putStr(r.DstNetworkRole)
		putStr(r.SrcRole)
		putStr(r.DstRole)
		putStr(r.SrcEntity)
		putStr(r.DstEntity)
		putUvarint(uint64(r.SrcVLAN))
		putUvarint(uint64(r.DstVLAN))
		putUvarint(uint64(r.Etype))
		putUvarint(uint64(r.Proto))
		putUvarint(uint64(r.SrcPort))
		putUvarint(uint64(r.DstPort))
		putUvarint(r.Bytes)
		putUvarint(r.Packets)
		buf.Write(r.SrcMAC[:])
		buf.Write(r.DstMAC[:])
		putUvarint(uint64(r.InIf))
		putUvarint(uint64(r.OutIf))
		buf.WriteByte(r.TCPFlags)
		buf.WriteByte(r.IPTTL)
		buf.WriteByte(r.IPTos)
	}

	// Copy out of the pooled buffer: the caller (buildFrame) needs a stable
	// slice while we return the buffer to the pool for reuse.
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

var errSpoolTruncated = errors.New("spool binary frame truncated")

// binCursor is a zero-allocation reader over the frame payload.
type binCursor struct {
	b   []byte
	pos int
}

func (c *binCursor) uvarint() (uint64, error) {
	v, n := binary.Uvarint(c.b[c.pos:])
	if n <= 0 {
		return 0, errSpoolTruncated
	}
	c.pos += n
	return v, nil
}

func (c *binCursor) i64() (int64, error) {
	if c.pos+8 > len(c.b) {
		return 0, errSpoolTruncated
	}
	v := binary.LittleEndian.Uint64(c.b[c.pos : c.pos+8])
	c.pos += 8
	return int64(v), nil
}

func (c *binCursor) timeField() (time.Time, error) {
	ns, err := c.i64()
	if err != nil {
		return time.Time{}, err
	}
	if ns == spoolZeroTimeSentinel {
		return time.Time{}, nil
	}
	return time.Unix(0, ns).UTC(), nil
}

func (c *binCursor) addr16() ([16]byte, error) {
	var a [16]byte
	if c.pos+16 > len(c.b) {
		return a, errSpoolTruncated
	}
	copy(a[:], c.b[c.pos:c.pos+16])
	c.pos += 16
	return a, nil
}

func (c *binCursor) u8() (uint8, error) {
	if c.pos+1 > len(c.b) {
		return 0, errSpoolTruncated
	}
	v := c.b[c.pos]
	c.pos++
	return v, nil
}

func (c *binCursor) mac6() ([6]byte, error) {
	var m [6]byte
	if c.pos+6 > len(c.b) {
		return m, errSpoolTruncated
	}
	copy(m[:], c.b[c.pos:c.pos+6])
	c.pos += 6
	return m, nil
}

func (c *binCursor) str() (string, error) {
	n, err := c.uvarint()
	if err != nil {
		return "", err
	}
	if n > uint64(len(c.b)-c.pos) {
		return "", errSpoolTruncated
	}
	s := string(c.b[c.pos : c.pos+int(n)])
	c.pos += int(n)
	return s, nil
}

// decodeFlowRowsBinary decodes a current-format (version 3, MAC-bearing) binary
// payload. It is the symmetric counterpart of encodeFlowRowsBinary and is used
// by round-trip callers and tests.
func decodeFlowRowsBinary(b []byte) ([]FlowRow, error) {
	return decodeFlowRowsBinaryVersion(b, true, true)
}

// decodeFlowRowsBinaryVersion decodes a binary payload. When hasMAC is false the
// trailing SrcMAC/DstMAC pair is absent (legacy frame version 2) and the MAC
// fields are left zero. When true (frame version 3+) the pair is read per row.
// When hasMeta is true (frame version 4) the trailing sFlow metadata
// (InIf/OutIf/TCPFlags/IPTTL/IPTos) is also read; otherwise those fields stay
// zero.
func decodeFlowRowsBinaryVersion(b []byte, hasMAC, hasMeta bool) ([]FlowRow, error) {
	c := binCursor{b: b}
	count, err := c.uvarint()
	if err != nil {
		return nil, err
	}
	if count > spoolMaxFrameRows {
		return nil, fmt.Errorf("spool binary frame row count %d exceeds max %d", count, spoolMaxFrameRows)
	}
	rows := make([]FlowRow, count)
	for i := uint64(0); i < count; i++ {
		r := &rows[i]
		if r.Date, err = c.timeField(); err != nil {
			return nil, err
		}
		if r.TimeInsertedNs, err = c.timeField(); err != nil {
			return nil, err
		}
		if r.TimeReceivedNs, err = c.timeField(); err != nil {
			return nil, err
		}
		if r.TimeFlowStartNs, err = c.timeField(); err != nil {
			return nil, err
		}

		var u uint64
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.SequenceNum = uint32(u)
		if r.SamplingRate, err = c.uvarint(); err != nil {
			return nil, err
		}
		if r.SamplerAddress, err = c.addr16(); err != nil {
			return nil, err
		}
		if r.SourceID, err = c.str(); err != nil {
			return nil, err
		}
		if r.SrcAddr, err = c.addr16(); err != nil {
			return nil, err
		}
		if r.DstAddr, err = c.addr16(); err != nil {
			return nil, err
		}
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.SrcAS = uint32(u)
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.DstAS = uint32(u)
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.SrcASN = uint32(u)
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.DstASN = uint32(u)

		strFields := []*string{
			&r.Direction, &r.SrcKind, &r.DstKind, &r.SrcLabel, &r.DstLabel,
			&r.SrcOperator, &r.DstOperator,
			&r.SrcAttachmentKind, &r.DstAttachmentKind,
			&r.SrcAttachmentBoundary, &r.DstAttachmentBoundary,
			&r.SrcAttachmentLabel, &r.DstAttachmentLabel,
			&r.SrcAttachmentOperator, &r.DstAttachmentOperator,
			&r.SrcEndpointScope, &r.DstEndpointScope,
			&r.SrcEndpointSource, &r.DstEndpointSource,
			&r.SrcNetworkName, &r.DstNetworkName,
			&r.SrcNetworkRole, &r.DstNetworkRole,
			&r.SrcRole, &r.DstRole, &r.SrcEntity, &r.DstEntity,
		}
		for _, dst := range strFields {
			if *dst, err = c.str(); err != nil {
				return nil, err
			}
		}

		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.SrcVLAN = uint16(u)
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.DstVLAN = uint16(u)
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.Etype = uint32(u)
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.Proto = uint32(u)
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.SrcPort = uint32(u)
		if u, err = c.uvarint(); err != nil {
			return nil, err
		}
		r.DstPort = uint32(u)
		if r.Bytes, err = c.uvarint(); err != nil {
			return nil, err
		}
		if r.Packets, err = c.uvarint(); err != nil {
			return nil, err
		}
		if hasMAC {
			if r.SrcMAC, err = c.mac6(); err != nil {
				return nil, err
			}
			if r.DstMAC, err = c.mac6(); err != nil {
				return nil, err
			}
		}
		if hasMeta {
			if u, err = c.uvarint(); err != nil {
				return nil, err
			}
			r.InIf = uint32(u)
			if u, err = c.uvarint(); err != nil {
				return nil, err
			}
			r.OutIf = uint32(u)
			if r.TCPFlags, err = c.u8(); err != nil {
				return nil, err
			}
			if r.IPTTL, err = c.u8(); err != nil {
				return nil, err
			}
			if r.IPTos, err = c.u8(); err != nil {
				return nil, err
			}
		}
	}
	if c.pos != len(b) {
		return nil, fmt.Errorf("spool binary frame has %d trailing bytes", len(b)-c.pos)
	}
	return rows, nil
}
