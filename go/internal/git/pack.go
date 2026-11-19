// Packfile read/write, the pkt-line codec, and fetch planning.
//
// Performance notes (see GHC-RESEARCH.md §5):
//   - P0-1: pooled zlib writer/reader with Reset, never fresh per object.
//   - P0-2: zlib level 1 (BestSpeed) for pack generation, after pooling.
//   - P0-3: whole-pack / whole-response caching lives in httpapi (it owns
//     the repo generation); this package supplies the per-object
//     compressed-entry cache (P0-4) so a cache miss is still memcpy-bound.
//   - P1-1: manual hex parse for pkt-line lengths (no fmt.Sscanf).
//   - P1-4: single-hash PackRead — each plain object is hashed once and
//     the index is reused by the delta resolver.
//   - P1-5: exact consumed-count zlib parsing over []byte + cursor
//     (bytes.Reader as io.ByteReader — no bufio over-read).
//   - P1-6: resolved-object cache — delta resolution memoizes every
//     resolved object, so a delta base is inflated/applied once.
package git

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"sync"
)

// ---------------------------------------------------------------- pkt-line

// Pkt-line framing (git's wire format): a data packet is 4 ASCII
// lowercase-hex bytes giving the length of (payload + 4), then the
// payload. Length counts the 4 header bytes; max packet 65520.
// Flush is "0000", delim "0001", response-end "0002".
const (
	// PktLineMax is git's LARGE_PACKET_MAX: the largest pkt-line
	// including its 4-byte length header.
	PktLineMax = 65520
	// PktLineMaxPayload is the largest pkt-line payload.
	PktLineMaxPayload = PktLineMax - 4
	// sidebandMaxPayload is the largest data chunk in one sideband
	// packet: payload minus the 1 band byte.
	sidebandMaxPayload = PktLineMaxPayload - 1
)

// PktKind is the kind of a decoded pkt-line packet.
type PktKind int

const (
	// PktData is a data packet carrying Payload.
	PktData PktKind = iota
	// PktFlush is the 0000 flush packet.
	PktFlush
	// PktDelim is the 0001 delim packet.
	PktDelim
	// PktResponseEnd is the 0002 response-end packet.
	PktResponseEnd
)

// ErrPktLine is returned for malformed pkt-line input (bad hex header,
// length 0003, length over the maximum, truncated packet). It is never
// a panic: callers turn it into a 400 or a band-3 error.
var ErrPktLine = errors.New("git: malformed pkt-line")

// appendPktLen appends the 4-hex length header for a payload of n bytes
// (total length n+4, including the header). Manual hex, no Sprintf.
func appendPktLen(dst []byte, n int) []byte {
	total := n + 4
	return append(dst,
		hexDigits[(total>>12)&0xf],
		hexDigits[(total>>8)&0xf],
		hexDigits[(total>>4)&0xf],
		hexDigits[total&0xf],
	)
}

// EncodePktLine appends one framed data packet for payload to dst.
// Payloads over PktLineMaxPayload are the caller's bug; they are
// truncated to the maximum rather than producing an invalid packet.
func EncodePktLine(dst, payload []byte) []byte {
	if len(payload) > PktLineMaxPayload {
		payload = payload[:PktLineMaxPayload]
	}
	dst = appendPktLen(dst, len(payload))
	return append(dst, payload...)
}

// EncodePktLineString appends one framed data packet for the string s.
func EncodePktLineString(dst []byte, s string) []byte {
	if len(s) > PktLineMaxPayload {
		s = s[:PktLineMaxPayload]
	}
	dst = appendPktLen(dst, len(s))
	return append(dst, s...)
}

// AppendPktFlush appends a flush packet ("0000").
func AppendPktFlush(dst []byte) []byte { return append(dst, '0', '0', '0', '0') }

// AppendPktDelim appends a delim packet ("0001").
func AppendPktDelim(dst []byte) []byte { return append(dst, '0', '0', '0', '1') }

// parsePktLen parses 4 hex bytes into a length, or -1 when any byte is
// not hex. Manual hex parse (P1-1): ~50x cheaper than fmt.Sscanf.
func parsePktLen(b []byte) int {
	hi0, lo0 := hexVal[b[0]], hexVal[b[1]]
	hi1, lo1 := hexVal[b[2]], hexVal[b[3]]
	if hi0 < 0 || lo0 < 0 || hi1 < 0 || lo1 < 0 {
		return -1
	}
	return int(hi0)<<12 | int(lo0)<<8 | int(hi1)<<4 | int(lo1)
}

// PktDecoder decodes pkt-lines from a byte slice with a cursor, so
// callers can stop at a flush and take the remaining bytes raw (a
// receive-pack's pack follows its command list unframed).
type PktDecoder struct {
	data []byte
	pos  int
}

// NewPktDecoder builds a decoder over data.
func NewPktDecoder(data []byte) *PktDecoder { return &PktDecoder{data: data} }

// Pos returns the cursor: the offset just past the last decoded packet.
func (d *PktDecoder) Pos() int { return d.pos }

// Rest returns the bytes not yet consumed.
func (d *PktDecoder) Rest() []byte { return d.data[d.pos:] }

// Exhausted reports whether every byte has been consumed.
func (d *PktDecoder) Exhausted() bool { return d.pos >= len(d.data) }

// Next decodes the next packet. It returns (PktData, payload, nil) for a
// data packet (payload aliases d's bytes — do not mutate), a control
// kind with a nil payload for flush/delim/response-end, or an error on
// malformed input. io.EOF is returned when no bytes remain.
func (d *PktDecoder) Next() (PktKind, []byte, error) {
	if d.pos >= len(d.data) {
		return PktData, nil, io.EOF
	}
	if len(d.data)-d.pos < 4 {
		return PktData, nil, ErrPktLine
	}
	n := parsePktLen(d.data[d.pos : d.pos+4])
	if n < 0 {
		return PktData, nil, ErrPktLine
	}
	switch n {
	case 0:
		d.pos += 4
		return PktFlush, nil, nil
	case 1:
		d.pos += 4
		return PktDelim, nil, nil
	case 2:
		d.pos += 4
		return PktResponseEnd, nil, nil
	case 3:
		return PktData, nil, ErrPktLine
	}
	if n > PktLineMax {
		return PktData, nil, ErrPktLine
	}
	if len(d.data)-d.pos < n {
		return PktData, nil, ErrPktLine
	}
	payload := d.data[d.pos+4 : d.pos+n]
	d.pos += n
	return PktData, payload, nil
}

// AppendSideband appends data as band-N sideband packets (each pkt-line
// payload is 1 band byte + up to 65515 data bytes). Band 1 is pack
// bytes, band 2 progress, band 3 fatal errors.
func AppendSideband(dst []byte, band byte, data []byte) []byte {
	for len(data) > 0 {
		chunk := data
		if len(chunk) > sidebandMaxPayload {
			chunk = chunk[:sidebandMaxPayload]
		}
		dst = appendPktLen(dst, len(chunk)+1)
		dst = append(dst, band)
		dst = append(dst, chunk...)
		data = data[len(chunk):]
	}
	return dst
}

// ---------------------------------------------------------------- objects

// Object is one git object: its id, type, and exact bytes.
type Object struct {
	SHA  string
	Type string
	Data []byte
}

// ObjectStore is the read side of the object store the fetch planner
// and the pack reader need. The store.Store satisfies it.
type ObjectStore interface {
	// GetObject returns an object's bytes and type. The returned slice
	// is store-owned: callers must treat it as read-only.
	GetObject(sha string) (data []byte, typ string, ok bool)
}

// ---------------------------------------------------------------- pack write

// Pooled zlib writers (P0-1) at level 1 (P0-2, BestSpeed). Constructing
// a flate writer (hash tables) dominates the compression itself, so a
// fresh writer per object costs ~10x a pooled one.
var zlibWriterPool = sync.Pool{
	New: func() any {
		w, err := zlib.NewWriterLevel(nil, 1)
		if err != nil {
			// Level 1 is always valid; unreachable in practice.
			w, _ = zlib.NewWriterLevel(nil, zlib.DefaultCompression)
		}
		return w
	},
}

// pooled buffers for zlib output.
var packBufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

// compressedEntryCache is the per-object compressed pack-entry cache
// (P0-4): the full pack entry bytes (varint header + zlib stream) for
// an object, keyed by sha. Objects are immutable, so an entry is valid
// forever. Clone assembly becomes memcpy of cached entries.
const compressedEntryCap = 32 << 20 // 32 MiB

var (
	compressedEntryMu    sync.RWMutex
	compressedEntryCache = make(map[string][]byte, 1024)
	compressedEntryBytes int
)

// appendPackObjectHeader appends a pack entry's type/size varint header:
// first byte [cont|type(3)|size-low-4], following bytes [cont|size-7]
// little-endian 7-bit groups.
func appendPackObjectHeader(dst []byte, typeCode, size int) []byte {
	first := byte(typeCode<<4) | byte(size&0x0f)
	size >>= 4
	for size > 0 {
		dst = append(dst, first|0x80)
		first = byte(size & 0x7f)
		size >>= 7
	}
	return append(dst, first)
}

// compressedEntry returns the full pack entry bytes (header + zlib
// stream) for one object, from the cache when present, else by
// compressing with a pooled level-1 writer and caching the result.
func compressedEntry(obj Object) []byte {
	compressedEntryMu.RLock()
	if entry, ok := compressedEntryCache[obj.SHA]; ok {
		compressedEntryMu.RUnlock()
		return entry
	}
	compressedEntryMu.RUnlock()

	buf := packBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(len(obj.Data)/2 + 64)
	w := zlibWriterPool.Get().(*zlib.Writer)
	w.Reset(buf)
	_, _ = w.Write(obj.Data)
	_ = w.Close()
	zlibWriterPool.Put(w)

	entry := make([]byte, 0, len(buf.Bytes())+8)
	entry = appendPackObjectHeader(entry, TypeCode(obj.Type), len(obj.Data))
	entry = append(entry, buf.Bytes()...)
	packBufPool.Put(buf)

	compressedEntryMu.Lock()
	if compressedEntryBytes+len(entry) > compressedEntryCap {
		// Simple eviction: drop everything. The trial's working set
		// (one 200-commit repo) is far below the cap, so this is a
		// safety valve, not a routine path.
		compressedEntryCache = make(map[string][]byte, 1024)
		compressedEntryBytes = 0
	}
	if _, dup := compressedEntryCache[obj.SHA]; !dup {
		compressedEntryCache[obj.SHA] = entry
		compressedEntryBytes += len(entry)
	} else {
		entry = compressedEntryCache[obj.SHA]
	}
	compressedEntryMu.Unlock()
	return entry
}

// BuildPack assembles a plain (undeltified) pack from objects: header
// (PACK + version 2 + count), one entry per object, trailer SHA-1 over
// everything before it. No deltas: the suite accepts 0-delta packs and
// generating deltas costs CPU the clone bench cannot spare. The output
// buffer is pre-sized from the entry sizes (P0-9).
func BuildPack(objects []Object) []byte {
	entries := make([][]byte, len(objects))
	total := 12 + 20
	for i, obj := range objects {
		entries[i] = compressedEntry(obj)
		total += len(entries[i])
	}
	out := make([]byte, 0, total)
	out = append(out, 'P', 'A', 'C', 'K')
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 2)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(objects)))
	out = append(out, hdr[:]...)
	for _, entry := range entries {
		out = append(out, entry...)
	}
	sum := sha1.Sum(out)
	return append(out, sum[:]...)
}

// EmptyPack is the 32-byte pack with zero objects (12-byte header +
// 20-byte trailer), precomputed once.
var EmptyPack = BuildPack(nil)

// ---------------------------------------------------------------- pack read

// Limits guarding the pack reader against hostile input. The suite's
// packs are far below every one of these.
const (
	maxPackObjects     = 1 << 20   // 1M objects per pack
	maxPackObjectBytes = 64 << 20  // 64 MiB per inflated object
	maxPackTotalBytes  = 512 << 20 // 512 MiB inflated per pack
	maxDeltaDepth      = 512       // max delta-chain recursion depth
)

// Pack errors. ReadPack returns these (wrapped with context) for
// malformed packs; callers turn them into an unpack error report.
var (
	ErrPackTruncated = errors.New("git: pack truncated")
	ErrPackHeader    = errors.New("git: bad pack header")
	ErrPackVersion   = errors.New("git: unsupported pack version")
	ErrPackType      = errors.New("git: unknown pack entry type")
	ErrPackSize      = errors.New("git: pack entry size mismatch")
	ErrPackTrailer   = errors.New("git: pack trailer checksum mismatch")
	ErrPackTrailing  = errors.New("git: stray bytes before pack trailer")
	ErrDeltaBase     = errors.New("git: delta base not found")
	ErrDeltaCycle    = errors.New("git: delta cycle")
	ErrDeltaCorrupt  = errors.New("git: corrupt delta")
)

// Pooled zlib readers (P0-1). Reset with a bytes.Reader (an
// io.ByteReader) so the inflater never over-reads past one object's
// stream into the next entry's bytes (P1-5). Constructed over a valid
// empty zlib stream (78 01 + stored empty block + Adler-32 of "") so
// NewReader succeeds; Reset retargets it before any real use.
var zlibReaderPool = sync.Pool{
	New: func() any {
		r, _ := zlib.NewReader(bytes.NewReader([]byte{0x78, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01}))
		return r
	},
}

// rawEntry is one parsed pack entry before delta resolution.
type rawEntry struct {
	offset     int // byte offset of the entry header in the pack
	typeCode   int
	size       int    // inflated size (delta stream size for deltas)
	data       []byte // inflated bytes (delta instructions for deltas)
	baseOffset int    // OFS_DELTA: absolute offset of the base entry
	baseOID    string // REF_DELTA: object id of the base

	// Resolution memo (P1-6): filled once, reused by every delta that
	// names this entry as a base.
	resolved bool
	resType  string
	resData  []byte
	resOID   string
	inProg   bool // cycle detection during resolution
}

// packReader holds the state of one ReadPack call.
type packReader struct {
	pack       []byte
	trailerEnd int // offset of the trailer (= len(pack)-20)
	entries    []*rawEntry
	byOffset   map[int]*rawEntry
	byOID      map[string]*rawEntry // resolved entries by computed id
	lookup     func(sha string) (data []byte, typ string, ok bool)
	totalBytes int
}

// ReadPack parses a packfile and resolves every object, including
// OFS_DELTA and REF_DELTA in ONE unified DFS walk from the base
// (separate passes misclassify a REF-delta whose base is an OFS-delta
// in the same pack as an external thin-pack reference). lookup supplies
// base objects a thin pack leaves out (the store); it may be nil.
// Every plain object is hashed exactly once (P1-4); resolved objects
// are memoized (P1-6).
func ReadPack(pack []byte, lookup func(sha string) (data []byte, typ string, ok bool)) ([]Object, error) {
	if len(pack) < 32 {
		return nil, ErrPackTruncated
	}
	if string(pack[0:4]) != "PACK" {
		return nil, ErrPackHeader
	}
	version := binary.BigEndian.Uint32(pack[4:8])
	if version != 2 && version != 3 {
		return nil, ErrPackVersion
	}
	count := binary.BigEndian.Uint32(pack[8:12])
	if count > maxPackObjects {
		return nil, ErrPackHeader
	}
	trailerStart := len(pack) - 20
	sum := sha1.Sum(pack[:trailerStart])
	if !bytes.Equal(sum[:], pack[trailerStart:]) {
		return nil, ErrPackTrailer
	}

	pr := &packReader{
		pack:       pack,
		trailerEnd: trailerStart,
		entries:    make([]*rawEntry, 0, count),
		byOffset:   make(map[int]*rawEntry, count),
		byOID:      make(map[string]*rawEntry, count),
		lookup:     lookup,
	}
	offset := 12
	for i := uint32(0); i < count; i++ {
		entry, next, err := pr.parseEntry(offset)
		if err != nil {
			return nil, err
		}
		pr.entries = append(pr.entries, entry)
		pr.byOffset[entry.offset] = entry
		offset = next
	}
	if offset != trailerStart {
		return nil, ErrPackTrailing
	}

	// Resolve plain entries first (single hash each, P1-4), then
	// deltas in passes until all resolve. A REF-delta whose base is a
	// delta later in the pack defers to a later pass; a pass with no
	// progress means a missing base or a cycle.
	for _, e := range pr.entries {
		if e.typeCode != typeOfsDelta && e.typeCode != typeRefDelta {
			if err := pr.resolvePlain(e); err != nil {
				return nil, err
			}
		}
	}
	pending := make([]*rawEntry, 0)
	for _, e := range pr.entries {
		if e.typeCode == typeOfsDelta || e.typeCode == typeRefDelta {
			pending = append(pending, e)
		}
	}
	for len(pending) > 0 {
		progress := false
		remaining := pending[:0]
		for _, e := range pending {
			resolved, err := pr.resolveDelta(e, 0)
			if err != nil {
				if errors.Is(err, errBaseNotReady) {
					remaining = append(remaining, e)
					continue
				}
				return nil, err
			}
			if resolved {
				progress = true
			} else {
				remaining = append(remaining, e)
			}
		}
		pending = remaining
		if !progress {
			return nil, ErrDeltaBase
		}
	}

	out := make([]Object, len(pr.entries))
	for i, e := range pr.entries {
		out[i] = Object{SHA: e.resOID, Type: e.resType, Data: e.resData}
	}
	return out, nil
}

// errBaseNotReady marks a delta whose base is not resolvable yet in
// this pass (a REF-delta naming a delta entry that resolves later).
var errBaseNotReady = errors.New("git: delta base not ready")

// parseEntry parses one pack entry at offset: the type/size varint,
// the OFS base offset or REF base id, then the zlib stream (inflated
// with exact consumed-count tracking, P1-5). It returns the entry and
// the offset just past the zlib stream.
func (pr *packReader) parseEntry(offset int) (*rawEntry, int, error) {
	if offset >= pr.trailerEnd {
		return nil, 0, ErrPackTruncated
	}
	// Type/size varint: first byte [cont|type(3)|size-low-4], then
	// 7-bit groups shifting left from bit 4.
	first := pr.pack[offset]
	typeCode := int(first>>4) & 0x07
	size := int(first & 0x0f)
	shift := uint(4)
	pos := offset + 1
	for first&0x80 != 0 {
		if pos >= pr.trailerEnd {
			return nil, 0, ErrPackTruncated
		}
		b := pr.pack[pos]
		pos++
		if shift < 63 {
			size += int(b&0x7f) << shift
		} else if b&0x7f != 0 {
			return nil, 0, ErrPackHeader
		}
		shift += 7
		first = b
	}
	if size < 0 || size > maxPackObjectBytes {
		return nil, 0, ErrPackSize
	}
	pr.totalBytes += size
	if pr.totalBytes > maxPackTotalBytes {
		return nil, 0, ErrPackSize
	}
	entry := &rawEntry{offset: offset, typeCode: typeCode, size: size}
	switch typeCode {
	case typeOfsDelta:
		// OFS base offset: first byte's low 7 bits, then while MSB
		// set: value = ((value+1)<<7) + (next & 0x7f). The value is
		// the negative offset from this entry's start.
		if pos >= pr.trailerEnd {
			return nil, 0, ErrPackTruncated
		}
		b := pr.pack[pos]
		pos++
		value := int(b & 0x7f)
		for b&0x80 != 0 {
			if pos >= pr.trailerEnd {
				return nil, 0, ErrPackTruncated
			}
			b = pr.pack[pos]
			pos++
			value = ((value + 1) << 7) + int(b&0x7f)
		}
		if value <= 0 || value > offset {
			return nil, 0, ErrDeltaBase
		}
		entry.baseOffset = offset - value
	case typeRefDelta:
		if pos+20 > pr.trailerEnd {
			return nil, 0, ErrPackTruncated
		}
		oid := make([]byte, 40)
		hexEncode20(oid, pr.pack[pos:pos+20])
		entry.baseOID = string(oid)
		pos += 20
	case typeCommit, typeTree, typeBlob, typeTag:
		// Plain entry.
	default:
		return nil, 0, ErrPackType
	}

	// Inflate the zlib stream starting at pos. bytes.Reader is an
	// io.ByteReader, so the pooled inflater consumes exactly this
	// stream's bytes (P1-5); the reader's position after EOF is the
	// next entry's offset.
	br := bytes.NewReader(pr.pack[pos:pr.trailerEnd])
	zr := zlibReaderPool.Get().(io.ReadCloser)
	// Reset needs a valid reader; a pooled reader constructed over an
	// empty stream is fine to Reset.
	if err := resetZlibReader(zr, br); err != nil {
		zlibReaderPool.Put(zr)
		return nil, 0, err
	}
	buf := packBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	buf.Grow(size)
	_, err := buf.ReadFrom(zr)
	_ = zr.Close()
	zlibReaderPool.Put(zr)
	if err != nil {
		packBufPool.Put(buf)
		return nil, 0, ErrPackSize
	}
	if buf.Len() != size {
		packBufPool.Put(buf)
		return nil, 0, ErrPackSize
	}
	data := make([]byte, buf.Len())
	copy(data, buf.Bytes())
	packBufPool.Put(buf)
	entry.data = data
	// Consumed bytes = total minus remaining in the bytes.Reader.
	consumed := (pr.trailerEnd - pos) - br.Len()
	return entry, pos + consumed, nil
}

// resetZlibReader resets a pooled zlib reader onto r. zlib.Reader's
// Reset takes (io.Reader, dict []byte).
func resetZlibReader(zr io.ReadCloser, r io.Reader) error {
	type resetter interface {
		Reset(io.Reader, []byte) error
	}
	if rs, ok := zr.(resetter); ok {
		return rs.Reset(r, nil)
	}
	return ErrPackSize
}

// resolvePlain hashes a plain entry once and indexes it by oid.
func (pr *packReader) resolvePlain(e *rawEntry) error {
	e.resType = TypeName(e.typeCode)
	var oid [40]byte
	hashObjectBytes(e.resType, e.data, oid[:])
	e.resOID = string(oid[:])
	e.resData = e.data
	e.resolved = true
	pr.byOID[e.resOID] = e
	return nil
}

// resolveDelta resolves one delta entry, recursing into its base when
// the base is itself a delta (the unified DFS walk). It returns
// (false, errBaseNotReady) when a REF base is not resolvable yet in
// this pass, (true, nil) on success, and a hard error otherwise.
func (pr *packReader) resolveDelta(e *rawEntry, depth int) (bool, error) {
	if e.resolved {
		return true, nil
	}
	if depth > maxDeltaDepth {
		return false, ErrDeltaCycle
	}
	if e.inProg {
		return false, ErrDeltaCycle
	}
	e.inProg = true
	defer func() { e.inProg = false }()

	var baseType string
	var baseData []byte
	switch e.typeCode {
	case typeOfsDelta:
		base := pr.byOffset[e.baseOffset]
		if base == nil {
			return false, ErrDeltaBase
		}
		if !base.resolved {
			if base.typeCode == typeOfsDelta || base.typeCode == typeRefDelta {
				ok, err := pr.resolveDelta(base, depth+1)
				if err != nil {
					return false, err
				}
				if !ok {
					return false, nil
				}
			} else {
				if err := pr.resolvePlain(base); err != nil {
					return false, err
				}
			}
		}
		baseType, baseData = base.resType, base.resData
	case typeRefDelta:
		if base, ok := pr.byOID[e.baseOID]; ok {
			if !base.resolved {
				// A byOID entry is always resolved (only resolved
				// entries are indexed); defensive only.
				return false, nil
			}
			baseType, baseData = base.resType, base.resData
		} else if pr.lookup != nil {
			data, typ, ok := pr.lookup(e.baseOID)
			if !ok {
				// The base may be a delta later in the pack that
				// has not resolved yet: defer to a later pass.
				return false, errBaseNotReady
			}
			baseType, baseData = typ, data
		} else {
			return false, errBaseNotReady
		}
	default:
		return false, ErrPackType
	}

	resolved, err := ApplyDelta(baseData, e.data)
	if err != nil {
		return false, err
	}
	e.resType = baseType
	e.resData = resolved
	var oid [40]byte
	hashObjectBytes(baseType, resolved, oid[:])
	e.resOID = string(oid[:])
	e.resolved = true
	pr.byOID[e.resOID] = e
	return true, nil
}

// ApplyDelta applies a git delta instruction stream to a base object's
// bytes. Format: source-size varint, target-size varint, then opcodes
// until the stream ends — copy (MSB set; size 0 means 0x10000) or
// insert (MSB clear, low 7 bits = literal length). Opcode 0 is invalid.
func ApplyDelta(base, delta []byte) ([]byte, error) {
	pos := 0
	readSize := func() (int, error) {
		value := 0
		shift := uint(0)
		for {
			if pos >= len(delta) {
				return 0, ErrDeltaCorrupt
			}
			b := delta[pos]
			pos++
			if shift < 63 {
				value += int(b&0x7f) << shift
			} else if b&0x7f != 0 {
				return 0, ErrDeltaCorrupt
			}
			shift += 7
			if b&0x80 == 0 {
				break
			}
		}
		return value, nil
	}
	sourceSize, err := readSize()
	if err != nil {
		return nil, err
	}
	targetSize, err := readSize()
	if err != nil {
		return nil, err
	}
	if sourceSize != len(base) {
		return nil, ErrDeltaCorrupt
	}
	if targetSize < 0 || targetSize > maxPackObjectBytes {
		return nil, ErrDeltaCorrupt
	}
	out := make([]byte, 0, targetSize)
	for pos < len(delta) {
		op := delta[pos]
		pos++
		if op&0x80 != 0 {
			// Copy from base: bits 0-3 select offset bytes,
			// bits 4-6 select size bytes, little-endian.
			copyOffset, copySize := 0, 0
			shift := uint(0)
			for bit := 0; bit < 4; bit++ {
				if op&(1<<uint(bit)) != 0 {
					if pos >= len(delta) {
						return nil, ErrDeltaCorrupt
					}
					copyOffset |= int(delta[pos]) << shift
					pos++
				}
				shift += 8
			}
			shift = 0
			for bit := 4; bit < 7; bit++ {
				if op&(1<<uint(bit)) != 0 {
					if pos >= len(delta) {
						return nil, ErrDeltaCorrupt
					}
					copySize |= int(delta[pos]) << shift
					pos++
				}
				shift += 8
			}
			if copySize == 0 {
				copySize = 0x10000
			}
			if copyOffset < 0 || copySize < 0 || copyOffset+copySize > len(base) {
				return nil, ErrDeltaCorrupt
			}
			if len(out)+copySize > targetSize {
				return nil, ErrDeltaCorrupt
			}
			out = append(out, base[copyOffset:copyOffset+copySize]...)
		} else if op != 0 {
			n := int(op & 0x7f)
			if pos+n > len(delta) {
				return nil, ErrDeltaCorrupt
			}
			if len(out)+n > targetSize {
				return nil, ErrDeltaCorrupt
			}
			out = append(out, delta[pos:pos+n]...)
			pos += n
		} else {
			return nil, ErrDeltaCorrupt
		}
	}
	if len(out) != targetSize {
		return nil, ErrDeltaCorrupt
	}
	return out, nil
}

// ---------------------------------------------------------------- fetch planning

// FetchRequest is one upload-pack fetch: what the client wants, what it
// already has, its current shallow boundary, and the depth limit
// (0 = no limit).
type FetchRequest struct {
	Wants   []string // wanted object ids
	Haves   []string // object ids the client already holds
	Shallow []string // the client's current shallow boundary commits
	Depth   int      // deepen N (0 = unlimited)
}

// FetchPlan is the result of PlanFetch: the objects to send (sorted by
// sha for determinism), the new shallow boundary, the commits that are
// no longer shallow, and the negotiation verdict.
type FetchPlan struct {
	Objects   []Object // objects to send, sorted by SHA
	Shallow   []string // new shallow boundary commits, sorted
	Unshallow []string // formerly-shallow commits now complete, sorted
	Acks      []string // haves that are ancestors of a want, sorted
	NAK       bool     // true when haves were sent but none matched
}

// ErrUnknownWant is returned when a wanted object is not in the store.
var ErrUnknownWant = errors.New("git: want object not found")

// PlanFetch computes the fetch set: objects reachable from wants within
// the depth limit, minus objects reachable from haves. It never
// re-sends an object the client holds, and it names the shallow
// boundary (depth-1 names the tip).
//
// Semantics (matching git + the conformance client):
//   - Haves prune the send set, but the depth walk still counts
//     generations through them (a deepen walks past the shallow have).
//   - The have-closure stops at the client's shallow boundary commits:
//     the client holds those commits but NOT their parents.
//   - A sent commit is shallow iff it has a parent the client will not
//     have after this fetch (neither sent nor already held).
//   - A formerly-shallow commit is unshallow iff one of its parents is
//     sent now.
func PlanFetch(st ObjectStore, req FetchRequest) (*FetchPlan, error) {
	plan := &FetchPlan{}

	// The client's shallow set, for have-closure pruning.
	clientShallow := make(map[string]bool, len(req.Shallow))
	for _, oid := range req.Shallow {
		clientShallow[oid] = true
	}

	// --- have closure: everything reachable from haves, stopping
	// parent traversal at client-shallow commits.
	haveSet := make(map[string]bool)
	if len(req.Haves) > 0 {
		collectReachable(st, req.Haves, clientShallow, haveSet)
	}

	// --- classify wants: commits seed the generation walk, tags peel
	// to their target (the tag object itself is sent), trees/blobs are
	// sent directly.
	var wantCommits []string
	var direct []string // tag/tree/blob wants (sent as-is, plus closure)
	seenWant := make(map[string]bool)
	for _, want := range req.Wants {
		if seenWant[want] {
			continue
		}
		seenWant[want] = true
		data, typ, ok := st.GetObject(want)
		if !ok {
			return nil, ErrUnknownWant
		}
		switch typ {
		case ObjCommit:
			wantCommits = append(wantCommits, want)
		case ObjTag:
			direct = append(direct, want)
			target := TagTarget(data)
			if target == "" {
				continue
			}
			if _, ttyp, ok := st.GetObject(target); ok {
				switch ttyp {
				case ObjCommit:
					wantCommits = append(wantCommits, target)
				case ObjTag:
					// Tag-to-tag: peel recursively.
					peeled := PeelTag(st, want)
					if peeled != "" {
						if _, ptyp, ok := st.GetObject(peeled); ok && ptyp == ObjCommit {
							wantCommits = append(wantCommits, peeled)
						} else if ok {
							direct = append(direct, peeled)
						}
					}
				default:
					direct = append(direct, target)
				}
			}
		default: // tree, blob
			direct = append(direct, want)
		}
	}

	// --- generation-limited walk from want commits. BFS by generation;
	// a commit is included when gen < Depth (Depth 0 = unlimited).
	// Traversal prunes at non-shallow haves (their ancestors are all
	// in haveSet, so nothing beyond them can be sent).
	included := make(map[string]bool) // commits in the send window
	if len(wantCommits) > 0 {
		type item struct {
			oid string
			gen int
		}
		queue := make([]item, 0, len(wantCommits))
		visited := make(map[string]bool, len(wantCommits))
		for _, c := range wantCommits {
			if !visited[c] {
				visited[c] = true
				queue = append(queue, item{c, 0})
			}
		}
		for head := 0; head < len(queue); head++ {
			cur := queue[head]
			if req.Depth > 0 && cur.gen >= req.Depth {
				continue
			}
			included[cur.oid] = true
			if haveSet[cur.oid] && !clientShallow[cur.oid] {
				continue // ancestors already held; prune
			}
			data, typ, ok := st.GetObject(cur.oid)
			if !ok || typ != ObjCommit {
				continue
			}
			commit, err := ParseCommitCached(cur.oid, data)
			if err != nil {
				continue
			}
			for _, p := range commit.Parents {
				if !visited[p] {
					visited[p] = true
					queue = append(queue, item{p, cur.gen + 1})
				}
			}
		}
	}

	// --- send set: closure of included commits + direct wants,
	// minus haveSet.
	sendSet := make(map[string]bool)
	// Direct wants (tags/trees/blobs) and their closures.
	for _, oid := range direct {
		collectIntoSendSet(st, oid, haveSet, sendSet)
	}
	// Included commits and their trees.
	for oid := range included {
		if haveSet[oid] {
			continue
		}
		sendSet[oid] = true
		data, typ, ok := st.GetObject(oid)
		if !ok || typ != ObjCommit {
			continue
		}
		commit, err := ParseCommitCached(oid, data)
		if err != nil {
			continue
		}
		collectIntoSendSet(st, commit.Tree, haveSet, sendSet)
	}

	// --- shallow boundary: a sent commit with a parent the client
	// will not have (neither sent nor already held).
	for oid := range included {
		if !sendSet[oid] {
			continue
		}
		data, typ, ok := st.GetObject(oid)
		if !ok || typ != ObjCommit {
			continue
		}
		commit, err := ParseCommitCached(oid, data)
		if err != nil {
			continue
		}
		for _, p := range commit.Parents {
			if !sendSet[p] && !haveSet[p] {
				plan.Shallow = append(plan.Shallow, oid)
				break
			}
		}
	}
	sort.Strings(plan.Shallow)

	// --- unshallow: a client-shallow commit gains a parent now.
	for _, oid := range req.Shallow {
		data, typ, ok := st.GetObject(oid)
		if !ok || typ != ObjCommit {
			continue
		}
		commit, err := ParseCommitCached(oid, data)
		if err != nil {
			continue
		}
		for _, p := range commit.Parents {
			if sendSet[p] {
				plan.Unshallow = append(plan.Unshallow, oid)
				break
			}
		}
	}
	sort.Strings(plan.Unshallow)

	// --- acknowledgments. No haves: no section at all (early exit —
	// the clone workload never has haves, so the ancestry walk is
	// skipped entirely). With haves: ACK each have that is an ancestor
	// of (or equal to) a want; NAK when none match.
	if len(req.Haves) > 0 {
		ancestors := make(map[string]bool)
		// Full ancestor walk from want commits (no depth limit).
		queue := append([]string(nil), wantCommits...)
		for _, d := range direct {
			ancestors[d] = true
		}
		visited := make(map[string]bool)
		for head := 0; head < len(queue); head++ {
			oid := queue[head]
			if visited[oid] {
				continue
			}
			visited[oid] = true
			ancestors[oid] = true
			data, typ, ok := st.GetObject(oid)
			if !ok || typ != ObjCommit {
				continue
			}
			commit, err := ParseCommitCached(oid, data)
			if err != nil {
				continue
			}
			queue = append(queue, commit.Parents...)
		}
		for _, h := range req.Haves {
			if ancestors[h] {
				plan.Acks = append(plan.Acks, h)
			}
		}
		sort.Strings(plan.Acks)
		if len(plan.Acks) == 0 {
			plan.NAK = true
		}
	}

	// --- materialize the send set, sorted by SHA for determinism.
	plan.Objects = make([]Object, 0, len(sendSet))
	for oid := range sendSet {
		data, typ, ok := st.GetObject(oid)
		if !ok {
			continue
		}
		plan.Objects = append(plan.Objects, Object{SHA: oid, Type: typ, Data: data})
	}
	sort.Slice(plan.Objects, func(i, j int) bool { return plan.Objects[i].SHA < plan.Objects[j].SHA })
	return plan, nil
}

// collectReachable adds everything reachable from roots to out:
// commit -> tree + parents, tree -> entries (gitlinks skipped), tag ->
// target. Parent traversal stops at commits in stopAtParents (the
// client's shallow boundary: held, but their parents are not).
// Missing objects are skipped (lenient: a have may name an object the
// store does not hold).
func collectReachable(st ObjectStore, roots []string, stopAtParents map[string]bool, out map[string]bool) {
	queue := append([]string(nil), roots...)
	for head := 0; head < len(queue); head++ {
		oid := queue[head]
		if out[oid] {
			continue
		}
		data, typ, ok := st.GetObject(oid)
		if !ok {
			continue
		}
		out[oid] = true
		switch typ {
		case ObjCommit:
			commit, err := ParseCommitCached(oid, data)
			if err != nil {
				continue
			}
			queue = append(queue, commit.Tree)
			if !stopAtParents[oid] {
				queue = append(queue, commit.Parents...)
			}
		case ObjTag:
			if target := TagTarget(data); target != "" {
				queue = append(queue, target)
			}
		case ObjTree:
			entries, err := ParseTreeCached(oid, data)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.Mode == "160000" {
					continue // gitlink: names a commit we do not hold
				}
				queue = append(queue, e.SHA)
			}
		}
	}
}

// collectIntoSendSet adds oid and its closure (tree entries, tag
// target, but NOT commit parents — the caller walks commits) to
// sendSet, skipping anything in haveSet.
func collectIntoSendSet(st ObjectStore, oid string, haveSet, sendSet map[string]bool) {
	queue := []string{oid}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		if sendSet[cur] || haveSet[cur] {
			continue
		}
		data, typ, ok := st.GetObject(cur)
		if !ok {
			continue
		}
		sendSet[cur] = true
		switch typ {
		case ObjTag:
			if target := TagTarget(data); target != "" {
				queue = append(queue, target)
			}
		case ObjTree:
			entries, err := ParseTreeCached(cur, data)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.Mode == "160000" {
					continue
				}
				queue = append(queue, e.SHA)
			}
		case ObjCommit:
			// A commit reached as a tag target or direct want: its
			// tree joins the send set, but its parents do not (the
			// generation walk owns parents).
			commit, err := ParseCommitCached(cur, data)
			if err != nil {
				continue
			}
			queue = append(queue, commit.Tree)
		}
	}
}

// PeelTag follows tag objects to the final non-tag target, or ""
// when the chain is broken or cyclic.
func PeelTag(st ObjectStore, oid string) string {
	seen := make(map[string]bool)
	for {
		if seen[oid] {
			return ""
		}
		seen[oid] = true
		data, typ, ok := st.GetObject(oid)
		if !ok {
			return ""
		}
		if typ != ObjTag {
			return oid
		}
		target := TagTarget(data)
		if target == "" {
			return ""
		}
		oid = target
	}
}

// PeelToCommit follows tag objects to a commit, returning the commit
// id or "" when the target is not a commit (or the chain is broken).
func PeelToCommit(st ObjectStore, oid string) string {
	peeled := PeelTag(st, oid)
	if peeled == "" {
		return ""
	}
	if _, typ, ok := st.GetObject(peeled); !ok || typ != ObjCommit {
		return ""
	}
	return peeled
}

// IsAncestor reports whether ancestor is an ancestor of (or equal to)
// descendant in the commit graph. Both must name commits (callers peel
// tags first). A missing object or parse failure yields false.
func IsAncestor(st ObjectStore, ancestor, descendant string) bool {
	if ancestor == descendant {
		return true
	}
	visited := make(map[string]bool)
	queue := []string{descendant}
	for head := 0; head < len(queue); head++ {
		oid := queue[head]
		if visited[oid] {
			continue
		}
		visited[oid] = true
		data, typ, ok := st.GetObject(oid)
		if !ok || typ != ObjCommit {
			continue
		}
		commit, err := ParseCommitCached(oid, data)
		if err != nil {
			continue
		}
		for _, p := range commit.Parents {
			if p == ancestor {
				return true
			}
			queue = append(queue, p)
		}
	}
	return false
}
