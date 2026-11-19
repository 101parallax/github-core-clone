package git

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// ---------------------------------------------------------------- pkt-line

func TestPktLineRoundTrip(t *testing.T) {
	var buf []byte
	buf = EncodePktLineString(buf, "version 2\n")
	buf = EncodePktLine(buf, []byte{1, 2, 3})
	buf = AppendPktFlush(buf)
	buf = AppendPktDelim(buf)
	buf = EncodePktLineString(buf, "")
	dec := NewPktDecoder(buf)
	kind, payload, err := dec.Next()
	if err != nil || kind != PktData || string(payload) != "version 2\n" {
		t.Fatalf("packet 1: kind=%v payload=%q err=%v", kind, payload, err)
	}
	kind, payload, err = dec.Next()
	if err != nil || kind != PktData || !bytes.Equal(payload, []byte{1, 2, 3}) {
		t.Fatalf("packet 2: kind=%v payload=%v err=%v", kind, payload, err)
	}
	kind, _, err = dec.Next()
	if err != nil || kind != PktFlush {
		t.Fatalf("packet 3: kind=%v err=%v", kind, err)
	}
	kind, _, err = dec.Next()
	if err != nil || kind != PktDelim {
		t.Fatalf("packet 4: kind=%v err=%v", kind, err)
	}
	kind, payload, err = dec.Next()
	if err != nil || kind != PktData || len(payload) != 0 {
		t.Fatalf("packet 5 (empty): kind=%v payload=%v err=%v", kind, payload, err)
	}
	if !dec.Exhausted() {
		t.Fatalf("decoder should be exhausted")
	}
	if _, _, err := dec.Next(); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestPktLineMalformed(t *testing.T) {
	for _, bad := range [][]byte{
		[]byte("zzzznot-a-pkt-line"),
		[]byte("0003"),
		[]byte("fffe"),     // length over max
		[]byte("0010ab"),   // truncated packet
		[]byte("00"),       // truncated header
		[]byte("000evers"), // truncated payload
	} {
		dec := NewPktDecoder(bad)
		if _, _, err := dec.Next(); err == nil {
			t.Fatalf("Next(%q): expected error", bad)
		}
	}
	// A valid packet followed by garbage: the first decodes, the
	// second errors (no panic).
	buf := EncodePktLineString(nil, "ok\n")
	buf = append(buf, []byte("zzzz")...)
	dec := NewPktDecoder(buf)
	if _, _, err := dec.Next(); err != nil {
		t.Fatalf("first packet: %v", err)
	}
	if _, _, err := dec.Next(); err == nil {
		t.Fatalf("expected error on garbage packet")
	}
}

func TestSidebandChunking(t *testing.T) {
	data := make([]byte, 70000)
	for i := range data {
		data[i] = byte(i)
	}
	framed := AppendSideband(nil, 1, data)
	// 70000 bytes -> 2 packets (65515 + 4485); each <= 65520 total.
	dec := NewPktDecoder(framed)
	var reassembled []byte
	packets := 0
	for !dec.Exhausted() {
		kind, payload, err := dec.Next()
		if err != nil || kind != PktData {
			t.Fatalf("packet %d: kind=%v err=%v", packets, kind, err)
		}
		if payload[0] != 1 {
			t.Fatalf("packet %d: band %d", packets, payload[0])
		}
		reassembled = append(reassembled, payload[1:]...)
		packets++
	}
	if packets != 2 {
		t.Fatalf("got %d packets, want 2", packets)
	}
	if !bytes.Equal(reassembled, data) {
		t.Fatalf("reassembled data differs")
	}
	// Every raw packet is within the max.
	if len(framed) > 2*PktLineMax {
		t.Fatalf("framing too large")
	}
}

// ---------------------------------------------------------------- pack round-trip

// testObjects builds a small object graph: 3 commits in a chain, trees,
// blobs, and an annotated tag on the tip.
func testObjects(t *testing.T) (objs []Object, tip, tagOID string) {
	t.Helper()
	blob1 := []byte("hello\n")
	blob2 := []byte("hello world\n")
	blob1OID := HashObject(ObjBlob, blob1)
	blob2OID := HashObject(ObjBlob, blob2)
	tree1 := BuildTree([]TreeEntry{{Mode: "100644", Name: "a.txt", SHA: blob1OID}})
	tree2 := BuildTree([]TreeEntry{{Mode: "100644", Name: "a.txt", SHA: blob2OID}})
	tree1OID := HashObject(ObjTree, tree1)
	tree2OID := HashObject(ObjTree, tree2)
	c1 := BuildCommit(tree1OID, nil, "A <a@x> 1700000000 +0000", "A <a@x> 1700000000 +0000", "one\n")
	c1OID := HashObject(ObjCommit, c1)
	c2 := BuildCommit(tree2OID, []string{c1OID}, "A <a@x> 1700000001 +0000", "A <a@x> 1700000001 +0000", "two\n")
	c2OID := HashObject(ObjCommit, c2)
	c3 := BuildCommit(tree2OID, []string{c2OID}, "A <a@x> 1700000002 +0000", "A <a@x> 1700000002 +0000", "three\n")
	c3OID := HashObject(ObjCommit, c3)
	tag := []byte("object " + c3OID + "\ntype commit\ntag v1\ntagger A <a@x> 1700000002 +0000\n\nv1\n")
	tagOID = HashObject(ObjTag, tag)
	objs = []Object{
		{SHA: blob1OID, Type: ObjBlob, Data: blob1},
		{SHA: blob2OID, Type: ObjBlob, Data: blob2},
		{SHA: tree1OID, Type: ObjTree, Data: tree1},
		{SHA: tree2OID, Type: ObjTree, Data: tree2},
		{SHA: c1OID, Type: ObjCommit, Data: c1},
		{SHA: c2OID, Type: ObjCommit, Data: c2},
		{SHA: c3OID, Type: ObjCommit, Data: c3},
		{SHA: tagOID, Type: ObjTag, Data: tag},
	}
	return objs, c3OID, tagOID
}

func TestPackRoundTrip(t *testing.T) {
	objs, _, _ := testObjects(t)
	pack := BuildPack(objs)
	// Trailer checksum.
	if len(pack) < 32 {
		t.Fatalf("pack too short: %d", len(pack))
	}
	sum := sha1.Sum(pack[:len(pack)-20])
	if !bytes.Equal(sum[:], pack[len(pack)-20:]) {
		t.Fatalf("trailer checksum mismatch")
	}
	if string(pack[0:4]) != "PACK" || binary.BigEndian.Uint32(pack[4:8]) != 2 {
		t.Fatalf("bad pack header")
	}
	if got := binary.BigEndian.Uint32(pack[8:12]); got != uint32(len(objs)) {
		t.Fatalf("declared count %d, want %d", got, len(objs))
	}
	got, err := ReadPack(pack, nil)
	if err != nil {
		t.Fatalf("ReadPack: %v", err)
	}
	if len(got) != len(objs) {
		t.Fatalf("read %d objects, want %d", len(got), len(objs))
	}
	want := make(map[string]Object, len(objs))
	for _, o := range objs {
		want[o.SHA] = o
	}
	for _, o := range got {
		w, ok := want[o.SHA]
		if !ok {
			t.Fatalf("unexpected object %s", o.SHA)
		}
		if o.Type != w.Type || !bytes.Equal(o.Data, w.Data) {
			t.Fatalf("object %s differs", o.SHA)
		}
	}
}

func TestPackEmpty(t *testing.T) {
	if len(EmptyPack) != 32 {
		t.Fatalf("empty pack is %d bytes, want 32", len(EmptyPack))
	}
	got, err := ReadPack(EmptyPack, nil)
	if err != nil {
		t.Fatalf("ReadPack(empty): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty pack yielded %d objects", len(got))
	}
	if !bytes.Equal(BuildPack(nil), EmptyPack) {
		t.Fatalf("BuildPack(nil) != EmptyPack")
	}
}

func TestPackCorrupt(t *testing.T) {
	objs, _, _ := testObjects(t)
	good := BuildPack(objs)
	// Bad trailer.
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xff
	if _, err := ReadPack(bad, nil); !errors.Is(err, ErrPackTrailer) {
		t.Fatalf("bad trailer: err=%v", err)
	}
	// Bad magic.
	bad = append([]byte(nil), good...)
	bad[0] = 'X'
	if _, err := ReadPack(bad, nil); !errors.Is(err, ErrPackHeader) {
		t.Fatalf("bad magic: err=%v", err)
	}
	// Bad version.
	bad = append([]byte(nil), good...)
	binary.BigEndian.PutUint32(bad[4:8], 4)
	sum := sha1.Sum(bad[:len(bad)-20])
	copy(bad[len(bad)-20:], sum[:])
	if _, err := ReadPack(bad, nil); !errors.Is(err, ErrPackVersion) {
		t.Fatalf("bad version: err=%v", err)
	}
	// Truncated.
	if _, err := ReadPack(good[:len(good)-5], nil); err == nil {
		t.Fatalf("truncated pack: expected error")
	}
	if _, err := ReadPack([]byte("short"), nil); !errors.Is(err, ErrPackTruncated) {
		t.Fatalf("short pack: err=%v", err)
	}
}

// ---------------------------------------------------------------- delta packs

// zlibCompress compresses data with a fresh zlib writer (test helper).
func zlibCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// packEntryHeader builds a pack entry's type/size varint header.
func packEntryHeader(typeCode, size int) []byte {
	var out []byte
	first := byte(typeCode<<4) | byte(size&0x0f)
	size >>= 4
	for size > 0 {
		out = append(out, first|0x80)
		first = byte(size & 0x7f)
		size >>= 7
	}
	return append(out, first)
}

// ofsOffset encodes a negative OFS-delta offset value.
func ofsOffset(value int) []byte {
	buf := []byte{byte(value & 0x7f)}
	value >>= 7
	for value > 0 {
		value--
		buf = append([]byte{0x80 | byte(value&0x7f)}, buf...)
		value >>= 7
	}
	return buf
}

// deltaVarint encodes a delta size varint (7-bit LE groups).
func deltaVarint(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n > 0 {
			out = append(out, b|0x80)
		} else {
			out = append(out, b)
			return out
		}
	}
}

// deltaInsert builds a delta that produces target from base using only
// insert opcodes (source size must equal len(base)).
func deltaInsert(base, target []byte) []byte {
	out := deltaVarint(len(base))
	out = append(out, deltaVarint(len(target))...)
	for len(target) > 0 {
		n := len(target)
		if n > 127 {
			n = 127
		}
		out = append(out, byte(n))
		out = append(out, target[:n]...)
		target = target[n:]
	}
	return out
}

// deltaCopyPrefix builds a delta that copies the first n bytes of base
// then inserts the rest of target.
func deltaCopyPrefix(base, target []byte, n int) []byte {
	out := deltaVarint(len(base))
	out = append(out, deltaVarint(len(target))...)
	// Copy op: offset 0, size n. Opcode 0x80 | size bits.
	// Size n as little-endian bytes; set bits 4..6 for present bytes.
	var sizeBytes []byte
	v := n
	for v > 0 {
		sizeBytes = append(sizeBytes, byte(v&0xff))
		v >>= 8
	}
	op := byte(0x80)
	for i := range sizeBytes {
		op |= 1 << uint(4+i)
	}
	out = append(out, op)
	out = append(out, sizeBytes...)
	rest := target[n:]
	for len(rest) > 0 {
		m := len(rest)
		if m > 127 {
			m = 127
		}
		out = append(out, byte(m))
		out = append(out, rest[:m]...)
		rest = rest[m:]
	}
	return out
}

// packBuilder assembles a pack from raw entries for delta tests.
type packBuilder struct {
	t       *testing.T
	entries [][]byte // full entry bytes (header + extra + zlib stream)
}

func (b *packBuilder) plain(typ string, data []byte) {
	hdr := packEntryHeader(TypeCode(typ), len(data))
	b.entries = append(b.entries, append(hdr, zlibCompress(b.t, data)...))
}

// ofsDelta appends an OFS-delta entry whose base is the entry at
// baseIndex (must already exist). Returns the entry's index.
func (b *packBuilder) ofsDelta(baseIndex int, delta []byte) int {
	// Compute the new entry's offset: header (12) + prior entries.
	offset := 12
	for _, e := range b.entries {
		offset += len(e)
	}
	baseOffset := 12
	for i := 0; i < baseIndex; i++ {
		baseOffset += len(b.entries[i])
	}
	hdr := packEntryHeader(typeOfsDelta, len(delta))
	hdr = append(hdr, ofsOffset(offset-baseOffset)...)
	b.entries = append(b.entries, append(hdr, zlibCompress(b.t, delta)...))
	return len(b.entries) - 1
}

// refDelta appends a REF-delta entry naming baseOID.
func (b *packBuilder) refDelta(baseOID string, delta []byte) int {
	hdr := packEntryHeader(typeRefDelta, len(delta))
	var raw [20]byte
	if !hexDecode40(baseOID, raw[:]) {
		b.t.Fatalf("bad base oid %s", baseOID)
	}
	hdr = append(hdr, raw[:]...)
	b.entries = append(b.entries, append(hdr, zlibCompress(b.t, delta)...))
	return len(b.entries) - 1
}

func (b *packBuilder) build() []byte {
	out := []byte{'P', 'A', 'C', 'K'}
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 2)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(b.entries)))
	out = append(out, hdr[:]...)
	for _, e := range b.entries {
		out = append(out, e...)
	}
	sum := sha1.Sum(out)
	return append(out, sum[:]...)
}

func TestPackDeltaOFSBaseIsREF(t *testing.T) {
	// Chain: plain A <- REF-delta B <- OFS-delta C.
	// The unified DFS must resolve C through B (a REF-delta base).
	a := []byte("base content for delta testing 0123456789")
	bContent := []byte("base content for delta testing 0123456789 + B suffix")
	cContent := []byte("base content for delta testing 0123456789 + B suffix + C suffix")
	aOID := HashObject(ObjBlob, a)
	bOID := HashObject(ObjBlob, bContent)
	cOID := HashObject(ObjBlob, cContent)

	pb := &packBuilder{t: t}
	pb.plain(ObjBlob, a)
	pb.refDelta(aOID, deltaInsert(a, bContent))
	pb.ofsDelta(1, deltaInsert(bContent, cContent))
	pack := pb.build()

	got, err := ReadPack(pack, nil)
	if err != nil {
		t.Fatalf("ReadPack: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d objects, want 3", len(got))
	}
	byOID := map[string][]byte{}
	for _, o := range got {
		byOID[o.SHA] = o.Data
	}
	if !bytes.Equal(byOID[aOID], a) || !bytes.Equal(byOID[bOID], bContent) || !bytes.Equal(byOID[cOID], cContent) {
		t.Fatalf("delta resolution mismatch: got oids %v", keysOf(byOID))
	}
}

func TestPackDeltaREFBaseIsOFS(t *testing.T) {
	// Chain: plain A <- OFS-delta B <- REF-delta C.
	// A separate-passes resolver would misclassify C's base (an
	// OFS-delta) as an external thin-pack reference.
	a := []byte("alpha bravo charlie delta")
	bContent := []byte("alpha bravo charlie delta echo")
	cContent := []byte("alpha bravo charlie delta echo foxtrot")
	aOID := HashObject(ObjBlob, a)
	bOID := HashObject(ObjBlob, bContent)
	cOID := HashObject(ObjBlob, cContent)

	pb := &packBuilder{t: t}
	pb.plain(ObjBlob, a)
	pb.ofsDelta(0, deltaCopyPrefix(a, bContent, len(a)))
	pb.refDelta(bOID, deltaInsert(bContent, cContent))
	pack := pb.build()

	got, err := ReadPack(pack, nil)
	if err != nil {
		t.Fatalf("ReadPack: %v", err)
	}
	byOID := map[string][]byte{}
	for _, o := range got {
		byOID[o.SHA] = o.Data
	}
	if !bytes.Equal(byOID[aOID], a) || !bytes.Equal(byOID[bOID], bContent) || !bytes.Equal(byOID[cOID], cContent) {
		t.Fatalf("delta resolution mismatch")
	}
}

func TestPackDeltaREFBaseLaterInPack(t *testing.T) {
	// REF-delta FIRST, its OFS-delta base later in the pack: the
	// resolver must defer the REF-delta to a later pass.
	a := []byte("one two three")
	bContent := []byte("one two three four")
	cContent := []byte("one two three four five")
	bOID := HashObject(ObjBlob, bContent)
	cOID := HashObject(ObjBlob, cContent)

	pb := &packBuilder{t: t}
	pb.refDelta(bOID, deltaInsert(bContent, cContent)) // index 0: C, base B not yet seen
	pb.plain(ObjBlob, a)                               // index 1: A
	pb.ofsDelta(1, deltaInsert(a, bContent))           // index 2: B (base A)
	pack := pb.build()

	got, err := ReadPack(pack, nil)
	if err != nil {
		t.Fatalf("ReadPack: %v", err)
	}
	byOID := map[string][]byte{}
	for _, o := range got {
		byOID[o.SHA] = o.Data
	}
	if !bytes.Equal(byOID[bOID], bContent) || !bytes.Equal(byOID[cOID], cContent) {
		t.Fatalf("later-base delta resolution mismatch")
	}
}

func TestPackThinREFDelta(t *testing.T) {
	// Thin pack: REF-delta whose base lives only in the external store.
	base := []byte("thin pack base object")
	target := []byte("thin pack base object extended")
	baseOID := HashObject(ObjBlob, base)
	targetOID := HashObject(ObjBlob, target)

	pb := &packBuilder{t: t}
	pb.refDelta(baseOID, deltaInsert(base, target))
	pack := pb.build()

	// Without a lookup the base is missing.
	if _, err := ReadPack(pack, nil); !errors.Is(err, ErrDeltaBase) {
		t.Fatalf("no lookup: err=%v, want ErrDeltaBase", err)
	}
	// With a lookup it resolves.
	got, err := ReadPack(pack, func(sha string) ([]byte, string, bool) {
		if sha == baseOID {
			return base, ObjBlob, true
		}
		return nil, "", false
	})
	if err != nil {
		t.Fatalf("ReadPack with lookup: %v", err)
	}
	if len(got) != 1 || got[0].SHA != targetOID || !bytes.Equal(got[0].Data, target) {
		t.Fatalf("thin resolution mismatch: %+v", got)
	}
}

func TestPackDeltaCorrupt(t *testing.T) {
	a := []byte("base")
	pb := &packBuilder{t: t}
	pb.plain(ObjBlob, a)
	// Delta claiming a wrong source size.
	bad := deltaVarint(999)
	bad = append(bad, deltaVarint(4)...)
	bad = append(bad, 4, 'x', 'x', 'x', 'x')
	pb.refDelta(HashObject(ObjBlob, a), bad)
	if _, err := ReadPack(pb.build(), nil); !errors.Is(err, ErrDeltaCorrupt) {
		t.Fatalf("corrupt delta: err=%v", err)
	}
	// Opcode 0.
	pb2 := &packBuilder{t: t}
	pb2.plain(ObjBlob, a)
	bad2 := deltaVarint(len(a))
	bad2 = append(bad2, deltaVarint(1)...)
	bad2 = append(bad2, 0)
	pb2.refDelta(HashObject(ObjBlob, a), bad2)
	if _, err := ReadPack(pb2.build(), nil); !errors.Is(err, ErrDeltaCorrupt) {
		t.Fatalf("opcode 0: err=%v", err)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------- ApplyDelta

func TestApplyDeltaCopySizeZero(t *testing.T) {
	// Copy size 0 means 0x10000: copy a full 64 KiB base.
	base := make([]byte, 0x10000)
	for i := range base {
		base[i] = byte(i >> 8)
	}
	// Delta: source size, target size, copy op with offset 0 and NO
	// size bytes (size 0 -> 0x10000).
	delta := deltaVarint(len(base))
	delta = append(delta, deltaVarint(len(base))...)
	delta = append(delta, 0x80) // copy, no offset/size bytes
	out, err := ApplyDelta(base, delta)
	if err != nil {
		t.Fatalf("ApplyDelta: %v", err)
	}
	if !bytes.Equal(out, base) {
		t.Fatalf("copy-0x10000 mismatch")
	}
}

func TestApplyDeltaErrors(t *testing.T) {
	base := []byte("0123456789")
	// Copy past the end of base.
	delta := deltaVarint(len(base))
	delta = append(delta, deltaVarint(20)...)
	delta = append(delta, 0x91, 8, 20) // copy offset 8, size 20
	if _, err := ApplyDelta(base, delta); !errors.Is(err, ErrDeltaCorrupt) {
		t.Fatalf("oob copy: err=%v", err)
	}
	// Output shorter than target size.
	delta = deltaVarint(len(base))
	delta = append(delta, deltaVarint(100)...)
	delta = append(delta, 1, 'x')
	if _, err := ApplyDelta(base, delta); !errors.Is(err, ErrDeltaCorrupt) {
		t.Fatalf("short output: err=%v", err)
	}
	// Truncated varint.
	if _, err := ApplyDelta(base, []byte{0x80}); !errors.Is(err, ErrDeltaCorrupt) {
		t.Fatalf("truncated varint: err=%v", err)
	}
}

// ---------------------------------------------------------------- fetch planning

// memStore is an in-memory ObjectStore for planner tests.
type memStore struct {
	objects map[string]Object
}

func (m *memStore) GetObject(sha string) ([]byte, string, bool) {
	o, ok := m.objects[sha]
	if !ok {
		return nil, "", false
	}
	return o.Data, o.Type, true
}

func (m *memStore) put(typ string, data []byte) string {
	oid := HashObject(typ, data)
	m.objects[oid] = Object{SHA: oid, Type: typ, Data: data}
	return oid
}

// chainFixture builds a 3-commit linear history plus a tag on the tip.
func chainFixture(t *testing.T) (*memStore, string, string, string, string) {
	t.Helper()
	st := &memStore{objects: make(map[string]Object)}
	mk := func(content string, parents []string) string {
		blob := st.put(ObjBlob, []byte(content))
		tree := st.put(ObjTree, BuildTree([]TreeEntry{{Mode: "100644", Name: "f.txt", SHA: blob}}))
		return st.put(ObjCommit, BuildCommit(tree, parents, "A <a@x> 1700000000 +0000", "A <a@x> 1700000000 +0000", content+"\n"))
	}
	c1 := mk("one", nil)
	c2 := mk("two", []string{c1})
	c3 := mk("three", []string{c2})
	tag := st.put(ObjTag, []byte("object "+c3+"\ntype commit\ntag v1\ntagger A <a@x> 1700000000 +0000\n\nv1\n"))
	return st, c1, c2, c3, tag
}

func oidSet(objs []Object) map[string]bool {
	out := make(map[string]bool, len(objs))
	for _, o := range objs {
		out[o.SHA] = true
	}
	return out
}

func TestPlanFetchFull(t *testing.T) {
	st, c1, _, c3, _ := chainFixture(t)
	plan, err := PlanFetch(st, FetchRequest{Wants: []string{c3}})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	// 3 commits + 3 trees + 3 blobs = 9 objects.
	if len(plan.Objects) != 9 {
		t.Fatalf("full fetch: %d objects, want 9", len(plan.Objects))
	}
	set := oidSet(plan.Objects)
	if !set[c1] || !set[c3] {
		t.Fatalf("full fetch missing commits")
	}
	if len(plan.Shallow) != 0 || len(plan.Acks) != 0 || plan.NAK {
		t.Fatalf("unexpected shallow/ack state: %+v", plan)
	}
}

func TestPlanFetchIncremental(t *testing.T) {
	st, c1, _, c3, _ := chainFixture(t)
	plan, err := PlanFetch(st, FetchRequest{Wants: []string{c3}, Haves: []string{c1}})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	set := oidSet(plan.Objects)
	if set[c1] {
		t.Fatalf("incremental fetch re-sent the have")
	}
	if !set[c3] {
		t.Fatalf("incremental fetch missing the tip")
	}
	// New: c2, c3 + 2 trees + 2 blobs = 6.
	if len(plan.Objects) != 6 {
		t.Fatalf("incremental fetch: %d objects, want 6", len(plan.Objects))
	}
	if len(plan.Acks) != 1 || plan.Acks[0] != c1 || plan.NAK {
		t.Fatalf("acks: %+v nak=%v", plan.Acks, plan.NAK)
	}
}

func TestPlanFetchNothingNew(t *testing.T) {
	st, _, _, c3, _ := chainFixture(t)
	plan, err := PlanFetch(st, FetchRequest{Wants: []string{c3}, Haves: []string{c3}})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	if len(plan.Objects) != 0 {
		t.Fatalf("nothing-new fetch sent %d objects", len(plan.Objects))
	}
	if len(plan.Acks) != 1 || plan.NAK {
		t.Fatalf("acks: %+v nak=%v", plan.Acks, plan.NAK)
	}
}

func TestPlanFetchNAK(t *testing.T) {
	st, _, _, c3, _ := chainFixture(t)
	// An unrelated have (a blob oid that is not an ancestor).
	unrelated := HashObject(ObjBlob, []byte("unrelated"))
	st.put(ObjBlob, []byte("unrelated"))
	plan, err := PlanFetch(st, FetchRequest{Wants: []string{c3}, Haves: []string{unrelated}})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	if !plan.NAK || len(plan.Acks) != 0 {
		t.Fatalf("expected NAK, got acks=%v nak=%v", plan.Acks, plan.NAK)
	}
}

func TestPlanFetchShallowDepth1(t *testing.T) {
	st, c1, c2, c3, _ := chainFixture(t)
	plan, err := PlanFetch(st, FetchRequest{Wants: []string{c3}, Depth: 1})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	set := oidSet(plan.Objects)
	if !set[c3] || set[c2] || set[c1] {
		t.Fatalf("depth-1 fetch sent wrong commits: %d objects", len(plan.Objects))
	}
	if len(plan.Objects) != 3 { // commit + tree + blob
		t.Fatalf("depth-1 fetch: %d objects, want 3", len(plan.Objects))
	}
	if len(plan.Shallow) != 1 || plan.Shallow[0] != c3 {
		t.Fatalf("shallow-info: %v, want [%s]", plan.Shallow, c3)
	}
}

func TestPlanFetchDeepen(t *testing.T) {
	st, c1, c2, c3, _ := chainFixture(t)
	plan, err := PlanFetch(st, FetchRequest{
		Wants:   []string{c3},
		Haves:   []string{c3},
		Shallow: []string{c3},
		Depth:   2,
	})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	set := oidSet(plan.Objects)
	if !set[c2] {
		t.Fatalf("deepen did not deliver the parent")
	}
	if set[c1] || set[c3] {
		t.Fatalf("deepen delivered wrong commits")
	}
	if len(plan.Shallow) != 1 || plan.Shallow[0] != c2 {
		t.Fatalf("shallow: %v, want [%s]", plan.Shallow, c2)
	}
	if len(plan.Unshallow) != 1 || plan.Unshallow[0] != c3 {
		t.Fatalf("unshallow: %v, want [%s]", plan.Unshallow, c3)
	}
}

func TestPlanFetchShallowNewTip(t *testing.T) {
	st, c1, c2, c3, _ := chainFixture(t)
	plan, err := PlanFetch(st, FetchRequest{
		Wants:   []string{c3},
		Haves:   []string{c2},
		Shallow: []string{c2},
		Depth:   1,
	})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	set := oidSet(plan.Objects)
	if !set[c3] || set[c2] || set[c1] {
		t.Fatalf("shallow new-tip fetch wrong: %d objects", len(plan.Objects))
	}
	// The tip's parent is held, so the tip is not a new boundary, and
	// the old boundary keeps its parent missing: no shallow-info.
	if len(plan.Shallow) != 0 || len(plan.Unshallow) != 0 {
		t.Fatalf("shallow-info: shallow=%v unshallow=%v", plan.Shallow, plan.Unshallow)
	}
}

func TestPlanFetchTagWant(t *testing.T) {
	st, _, _, c3, tag := chainFixture(t)
	plan, err := PlanFetch(st, FetchRequest{Wants: []string{tag}})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	set := oidSet(plan.Objects)
	if !set[tag] || !set[c3] {
		t.Fatalf("tag fetch missing tag/tip")
	}
	if len(plan.Objects) != 10 { // 9 + tag object
		t.Fatalf("tag fetch: %d objects, want 10", len(plan.Objects))
	}
}

func TestPlanFetchUnknownWant(t *testing.T) {
	st, _, _, _, _ := chainFixture(t)
	if _, err := PlanFetch(st, FetchRequest{Wants: []string{HashObject(ObjBlob, []byte("nope"))}}); !errors.Is(err, ErrUnknownWant) {
		t.Fatalf("unknown want: err=%v", err)
	}
}

func TestPlanFetchMergeDepth(t *testing.T) {
	st, c1, c2, _, _ := chainFixture(t)
	// Merge commit with parents c1 and c2.
	blob := st.put(ObjBlob, []byte("merged"))
	tree := st.put(ObjTree, BuildTree([]TreeEntry{{Mode: "100644", Name: "f.txt", SHA: blob}}))
	merge := st.put(ObjCommit, BuildCommit(tree, []string{c1, c2}, "A <a@x> 1700000000 +0000", "A <a@x> 1700000000 +0000", "merge\n"))
	plan, err := PlanFetch(st, FetchRequest{Wants: []string{merge}, Depth: 1})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	set := oidSet(plan.Objects)
	if !set[merge] || set[c1] || set[c2] {
		t.Fatalf("merge depth-1 wrong")
	}
	plan2, err := PlanFetch(st, FetchRequest{Wants: []string{merge}, Depth: 2})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	set2 := oidSet(plan2.Objects)
	if !set2[c1] || !set2[c2] {
		t.Fatalf("merge depth-2 missing parents")
	}
}

func TestIsAncestorAndPeel(t *testing.T) {
	st, c1, c2, c3, tag := chainFixture(t)
	if !IsAncestor(st, c1, c3) || !IsAncestor(st, c2, c3) || !IsAncestor(st, c3, c3) {
		t.Fatalf("IsAncestor false negative")
	}
	if IsAncestor(st, c3, c1) || IsAncestor(st, c2, c1) {
		t.Fatalf("IsAncestor false positive")
	}
	if got := PeelTag(st, tag); got != c3 {
		t.Fatalf("PeelTag(tag)=%s, want %s", got, c3)
	}
	if got := PeelTag(st, c3); got != c3 {
		t.Fatalf("PeelTag(commit)=%s, want %s", got, c3)
	}
	if got := PeelToCommit(st, tag); got != c3 {
		t.Fatalf("PeelToCommit(tag)=%s, want %s", got, c3)
	}
	// Tag-to-tag chain.
	tag2 := st.put(ObjTag, []byte("object "+tag+"\ntype tag\ntag v2\ntagger A <a@x> 1700000000 +0000\n\nv2\n"))
	if got := PeelTag(st, tag2); got != c3 {
		t.Fatalf("PeelTag(tag2)=%s, want %s", got, c3)
	}
	if got := PeelToCommit(st, tag2); got != c3 {
		t.Fatalf("PeelToCommit(tag2)=%s, want %s", got, c3)
	}
}

func TestPlanFetchDeterministicOrder(t *testing.T) {
	st, _, _, c3, _ := chainFixture(t)
	a, err := PlanFetch(st, FetchRequest{Wants: []string{c3}})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	b, err := PlanFetch(st, FetchRequest{Wants: []string{c3}})
	if err != nil {
		t.Fatalf("PlanFetch: %v", err)
	}
	if len(a.Objects) != len(b.Objects) {
		t.Fatalf("length differs")
	}
	for i := range a.Objects {
		if a.Objects[i].SHA != b.Objects[i].SHA {
			t.Fatalf("object order differs at %d", i)
		}
	}
	// Pack bytes must be byte-identical across builds.
	if !bytes.Equal(BuildPack(a.Objects), BuildPack(b.Objects)) {
		t.Fatalf("pack bytes differ across identical plans")
	}
}
