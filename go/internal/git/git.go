// Package git is the forge's git core: the object model (commit/tree/blob/tag),
// the pkt-line codec, packfile read/write with delta resolution, and fetch
// planning (reachability, shallow boundaries, have/want negotiation).
//
// Design rules:
//   - Objects are stored byte-exact. This package parses only to traverse
//     (parents, tree entries, tag targets); it never re-serializes a
//     stored object.
//   - Object ids are content SHA-1s, so parsed-commit/tree caches keyed by
//     sha are valid forever (objects are immutable). No generation needed.
//   - Hot paths avoid fmt.Sprintf/Sscanf entirely: hex is encoded/decoded
//     with tables, headers are built by hand.
package git

import (
	"crypto/sha1"
	"errors"
	"sort"
	"strconv"
	"sync"
)

// Object types, as git names them.
const (
	ObjCommit = "commit"
	ObjTree   = "tree"
	ObjBlob   = "blob"
	ObjTag    = "tag"
)

// ZeroOID is the all-zero object id: an unborn ref's value.
const ZeroOID = "0000000000000000000000000000000000000000"

// Pack type codes (git's pack format).
const (
	typeCommit   = 1
	typeTree     = 2
	typeBlob     = 3
	typeTag      = 4
	typeOfsDelta = 6
	typeRefDelta = 7
)

// hexDigits is the lowercase hex alphabet for manual encoding.
const hexDigits = "0123456789abcdef"

// hexVal maps an ASCII byte to its hex value, or -1 when not hex.
var hexVal [256]int8

func init() {
	for i := range hexVal {
		hexVal[i] = -1
	}
	for c := byte('0'); c <= '9'; c++ {
		hexVal[c] = int8(c - '0')
	}
	for c := byte('a'); c <= 'f'; c++ {
		hexVal[c] = int8(c-'a') + 10
	}
	for c := byte('A'); c <= 'F'; c++ {
		hexVal[c] = int8(c-'A') + 10
	}
}

// IsOID reports whether s is a lowercase 40-hex object id.
func IsOID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < 40; i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// hexEncode20 encodes 20 raw bytes as 40 lowercase hex characters.
func hexEncode20(dst []byte, src []byte) {
	for i, b := range src {
		dst[i*2] = hexDigits[b>>4]
		dst[i*2+1] = hexDigits[b&0x0f]
	}
}

// hexDecode40 decodes a 40-hex string into 20 bytes. It returns false
// when the input is not 40 hex characters.
func hexDecode40(s string, dst []byte) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < 20; i++ {
		hi := hexVal[s[i*2]]
		lo := hexVal[s[i*2+1]]
		if hi < 0 || lo < 0 {
			return false
		}
		dst[i] = byte(hi<<4 | lo)
	}
	return true
}

// HashObject returns the SHA-1 hex id of a git object
// (SHA-1 over "<type> <len>\0" + data). No Sprintf: the header is built
// by hand and the digest is hex-encoded with a table.
func HashObject(objType string, data []byte) string {
	h := sha1.New()
	// Header: "<type> <decimal len>\0", built without fmt.
	var hdr [32]byte
	n := copy(hdr[:], objType)
	hdr[n] = ' '
	n++
	n += len(strconv.AppendInt(hdr[n:n], int64(len(data)), 10))
	hdr[n] = 0
	n++
	h.Write(hdr[:n])
	h.Write(data)
	sum := h.Sum(nil)
	out := make([]byte, 40)
	hexEncode20(out, sum)
	return string(out)
}

// hashObjectBytes is HashObject writing into a caller-provided buffer.
func hashObjectBytes(objType string, data []byte, out []byte) {
	h := sha1.New()
	var hdr [32]byte
	n := copy(hdr[:], objType)
	hdr[n] = ' '
	n++
	n += len(strconv.AppendInt(hdr[n:n], int64(len(data)), 10))
	hdr[n] = 0
	n++
	h.Write(hdr[:n])
	h.Write(data)
	sum := h.Sum(nil)
	hexEncode20(out, sum)
}

// TypeCode returns the pack type code for an object type name,
// or 0 for an unknown type.
func TypeCode(objType string) int {
	switch objType {
	case ObjCommit:
		return typeCommit
	case ObjTree:
		return typeTree
	case ObjBlob:
		return typeBlob
	case ObjTag:
		return typeTag
	}
	return 0
}

// TypeName returns the object type name for a pack type code,
// or "" for delta/invalid codes.
func TypeName(code int) string {
	switch code {
	case typeCommit:
		return ObjCommit
	case typeTree:
		return ObjTree
	case typeBlob:
		return ObjBlob
	case typeTag:
		return ObjTag
	}
	return ""
}

// ---------------------------------------------------------------- commits

// Commit is a parsed commit object.
type Commit struct {
	Tree      string   // tree sha
	Parents   []string // parent shas, in order
	Author    string   // raw author line (name <email> ts tz)
	Committer string   // raw committer line
	Message   string   // commit message (after the blank line)
	Raw       []byte   // the exact stored bytes
}

// ErrMalformedCommit is returned for commit bytes with no valid tree
// header or with a malformed parent id.
var ErrMalformedCommit = errors.New("git: malformed commit")

// ParseCommit parses commit bytes. It returns an error on malformed
// input (missing/invalid tree header, bad parent id). Header lines the
// model does not know (gpgsig, encoding, ...) are ignored, matching the
// conformance client's parser.
func ParseCommit(data []byte) (*Commit, error) {
	c := &Commit{Raw: data}
	// Header runs to the first blank line; the message follows it.
	blank := -1
	for i := 0; i+1 < len(data); i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			blank = i
			break
		}
	}
	headerEnd := len(data)
	if blank >= 0 {
		headerEnd = blank
		c.Message = string(data[blank+2:])
	}
	// Walk header lines without splitting (no per-line allocation beyond
	// the strings the struct keeps).
	pos := 0
	for pos < headerEnd {
		eol := pos
		for eol < headerEnd && data[eol] != '\n' {
			eol++
		}
		line := data[pos:eol]
		pos = eol + 1
		if len(line) == 0 {
			continue
		}
		// key is up to the first space; value is the rest.
		sp := 0
		for sp < len(line) && line[sp] != ' ' {
			sp++
		}
		key := line[:sp]
		var val string
		if sp < len(line) {
			val = string(line[sp+1:])
		}
		switch string(key) {
		case "tree":
			c.Tree = val
		case "parent":
			c.Parents = append(c.Parents, val)
		case "author":
			c.Author = val
		case "committer":
			c.Committer = val
		}
	}
	if !IsOID(c.Tree) {
		return nil, ErrMalformedCommit
	}
	for _, p := range c.Parents {
		if !IsOID(p) {
			return nil, ErrMalformedCommit
		}
	}
	return c, nil
}

// BuildCommit serializes a commit (tree, parents, author, committer,
// message) to canonical git bytes. author/committer are raw ident lines
// ("name <email> ts tz"). The message is written as given.
func BuildCommit(tree string, parents []string, author, committer, message string) []byte {
	size := len("tree \n") + len(tree) +
		len("author \n") + len(author) +
		len("committer \n") + len(committer) +
		1 + len(message)
	for _, p := range parents {
		size += len("parent \n") + len(p)
	}
	out := make([]byte, 0, size)
	out = append(out, "tree "...)
	out = append(out, tree...)
	out = append(out, '\n')
	for _, p := range parents {
		out = append(out, "parent "...)
		out = append(out, p...)
		out = append(out, '\n')
	}
	out = append(out, "author "...)
	out = append(out, author...)
	out = append(out, '\n')
	out = append(out, "committer "...)
	out = append(out, committer...)
	out = append(out, '\n')
	out = append(out, '\n')
	out = append(out, message...)
	return out
}

// ---------------------------------------------------------------- tags

// Tag is a parsed annotated tag object.
type Tag struct {
	Object  string // target object id
	Type    string // target object type
	Tag     string // tag name
	Tagger  string // raw tagger line
	Message string // message (after the blank line)
	Raw     []byte // the exact stored bytes
}

// ErrMalformedTag is returned for tag bytes with no valid object header
// or an unknown target type.
var ErrMalformedTag = errors.New("git: malformed tag")

// ParseTag parses an annotated tag object.
func ParseTag(data []byte) (*Tag, error) {
	t := &Tag{Raw: data}
	blank := -1
	for i := 0; i+1 < len(data); i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			blank = i
			break
		}
	}
	headerEnd := len(data)
	if blank >= 0 {
		headerEnd = blank
		t.Message = string(data[blank+2:])
	}
	pos := 0
	for pos < headerEnd {
		eol := pos
		for eol < headerEnd && data[eol] != '\n' {
			eol++
		}
		line := data[pos:eol]
		pos = eol + 1
		if len(line) == 0 {
			continue
		}
		sp := 0
		for sp < len(line) && line[sp] != ' ' {
			sp++
		}
		key := line[:sp]
		var val string
		if sp < len(line) {
			val = string(line[sp+1:])
		}
		switch string(key) {
		case "object":
			t.Object = val
		case "type":
			t.Type = val
		case "tag":
			t.Tag = val
		case "tagger":
			t.Tagger = val
		}
	}
	if !IsOID(t.Object) {
		return nil, ErrMalformedTag
	}
	switch t.Type {
	case ObjCommit, ObjTree, ObjBlob, ObjTag:
	default:
		return nil, ErrMalformedTag
	}
	return t, nil
}

// TagTarget returns the target object id of tag bytes without a full
// parse, or "" when the bytes are not a parseable tag.
func TagTarget(data []byte) string {
	t, err := ParseTag(data)
	if err != nil {
		return ""
	}
	return t.Object
}

// ---------------------------------------------------------------- trees

// TreeEntry is one entry in a tree object.
type TreeEntry struct {
	Mode string // e.g. "100644", "40000"
	Name string
	SHA  string
}

// ErrMalformedTree is returned for tree bytes that do not parse.
var ErrMalformedTree = errors.New("git: malformed tree")

// ParseTree parses tree bytes into entries (in stored order).
func ParseTree(data []byte) ([]TreeEntry, error) {
	entries := make([]TreeEntry, 0, 8)
	pos := 0
	for pos < len(data) {
		// mode: ASCII octal up to the space.
		sp := pos
		for sp < len(data) && data[sp] != ' ' {
			sp++
		}
		if sp >= len(data) {
			return nil, ErrMalformedTree
		}
		mode := string(data[pos:sp])
		// name: up to the NUL.
		nul := sp + 1
		for nul < len(data) && data[nul] != 0 {
			nul++
		}
		if nul >= len(data) || nul+21 > len(data) {
			return nil, ErrMalformedTree
		}
		name := string(data[sp+1 : nul])
		oid := make([]byte, 40)
		hexEncode20(oid, data[nul+1:nul+21])
		entries = append(entries, TreeEntry{Mode: mode, Name: name, SHA: string(oid)})
		pos = nul + 21
	}
	return entries, nil
}

// treeEffByte returns byte i of a tree entry's effective sort name: the
// name itself, with a trailing '/' appended for directories (mode
// "40000"), or -1 past the end.
func treeEffByte(e TreeEntry, i int) int {
	if i < len(e.Name) {
		return int(e.Name[i])
	}
	if e.Mode == "40000" && i == len(e.Name) {
		return '/'
	}
	return -1
}

// treeEntryLess is git's tree sort order: byte order of the name, a
// directory compared as if its name ended in '/'. Allocation-free.
func treeEntryLess(a, b TreeEntry) bool {
	for i := 0; ; i++ {
		ca, cb := treeEffByte(a, i), treeEffByte(b, i)
		if ca < 0 && cb < 0 {
			// Identical effective names: tie-break on mode so the
			// order is deterministic even for duplicate names.
			return a.Mode < b.Mode
		}
		if ca < 0 {
			return true
		}
		if cb < 0 {
			return false
		}
		if ca != cb {
			return ca < cb
		}
	}
}

// SortTreeEntries sorts entries in git order (in place).
func SortTreeEntries(entries []TreeEntry) {
	sort.Slice(entries, func(i, j int) bool { return treeEntryLess(entries[i], entries[j]) })
}

// BuildTree serializes entries to canonical git bytes. Entries are
// sorted in git order first (the input slice is sorted in place, as the
// conformance client's buildTree does).
func BuildTree(entries []TreeEntry) []byte {
	SortTreeEntries(entries)
	size := 0
	for _, e := range entries {
		size += len(e.Mode) + 1 + len(e.Name) + 1 + 20
	}
	out := make([]byte, 0, size)
	var raw [20]byte
	for _, e := range entries {
		out = append(out, e.Mode...)
		out = append(out, ' ')
		out = append(out, e.Name...)
		out = append(out, 0)
		if !hexDecode40(e.SHA, raw[:]) {
			// Callers pass content hashes, so this never happens in
			// practice; zero bytes keep the length well-formed.
			for i := range raw {
				raw[i] = 0
			}
		}
		out = append(out, raw[:]...)
	}
	return out
}

// ---------------------------------------------------------------- parsed-object caches (P1-7)
//
// Objects are immutable and content-addressed, so a parsed commit/tree
// keyed by sha is valid forever. The fetch planner and the FF check walk
// the same commits repeatedly; parsing each once pays across walks.
// Bounded by entry count with clear-all eviction (trial repos are small;
// the cap is a safety valve, not a tuned size).

const parsedCacheMaxEntries = 100000

var (
	parsedCommitMu    sync.RWMutex
	parsedCommitCache = make(map[string]*Commit, 1024)
	parsedTreeMu      sync.RWMutex
	parsedTreeCache   = make(map[string][]TreeEntry, 1024)
)

// ParseCommitCached parses commit bytes, memoizing the result by sha.
// data must be the exact stored bytes for sha. A parse failure is not
// cached. The returned Commit (and its Raw slice) must not be mutated.
func ParseCommitCached(sha string, data []byte) (*Commit, error) {
	parsedCommitMu.RLock()
	c, ok := parsedCommitCache[sha]
	parsedCommitMu.RUnlock()
	if ok {
		return c, nil
	}
	c, err := ParseCommit(data)
	if err != nil {
		return nil, err
	}
	parsedCommitMu.Lock()
	if len(parsedCommitCache) >= parsedCacheMaxEntries {
		parsedCommitCache = make(map[string]*Commit, 1024)
	}
	parsedCommitCache[sha] = c
	parsedCommitMu.Unlock()
	return c, nil
}

// ParseTreeCached parses tree bytes, memoizing the result by sha.
// data must be the exact stored bytes for sha. A parse failure is not
// cached. The returned entries must not be mutated.
func ParseTreeCached(sha string, data []byte) ([]TreeEntry, error) {
	parsedTreeMu.RLock()
	entries, ok := parsedTreeCache[sha]
	parsedTreeMu.RUnlock()
	if ok {
		return entries, nil
	}
	entries, err := ParseTree(data)
	if err != nil {
		return nil, err
	}
	parsedTreeMu.Lock()
	if len(parsedTreeCache) >= parsedCacheMaxEntries {
		parsedTreeCache = make(map[string][]TreeEntry, 1024)
	}
	parsedTreeCache[sha] = entries
	parsedTreeMu.Unlock()
	return entries, nil
}
