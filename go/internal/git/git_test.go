package git

import (
	"crypto/sha1"
	"fmt"
	"testing"
)

// hashReference computes a git object id independently (fmt-based) so
// HashObject is checked against a second implementation, not itself.
func hashReference(objType string, data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", objType, len(data))
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestHashObjectKnownVectors(t *testing.T) {
	// The well-known empty blob and empty tree ids.
	if got := HashObject(ObjBlob, nil); got != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatalf("empty blob: got %s", got)
	}
	if got := HashObject(ObjTree, nil); got != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" {
		t.Fatalf("empty tree: got %s", got)
	}
}

func TestHashObjectMatchesReference(t *testing.T) {
	cases := []struct {
		typ  string
		data []byte
	}{
		{ObjBlob, []byte("hello world\n")},
		{ObjBlob, make([]byte, 100000)},
		{ObjCommit, []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nmsg\n")},
		{ObjTree, []byte("100644 a\x00")},
		{ObjTag, []byte("object e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\ntype blob\ntag v1\n\n")},
	}
	for _, c := range cases {
		if got, want := HashObject(c.typ, c.data), hashReference(c.typ, c.data); got != want {
			t.Fatalf("HashObject(%s, %d bytes): got %s, want %s", c.typ, len(c.data), got, want)
		}
	}
}

func TestCommitRoundTrip(t *testing.T) {
	tree := HashObject(ObjTree, nil)
	parent := HashObject(ObjBlob, []byte("x"))
	raw := BuildCommit(tree, []string{parent}, "Ada <ada@example.invalid> 1700000000 +0000", "Ada <ada@example.invalid> 1700000000 +0000", "hello\n\nbody\n")
	c, err := ParseCommit(raw)
	if err != nil {
		t.Fatalf("ParseCommit: %v", err)
	}
	if c.Tree != tree || len(c.Parents) != 1 || c.Parents[0] != parent {
		t.Fatalf("parents/tree mismatch: %+v", c)
	}
	if c.Author != "Ada <ada@example.invalid> 1700000000 +0000" {
		t.Fatalf("author: %q", c.Author)
	}
	if c.Message != "hello\n\nbody\n" {
		t.Fatalf("message: %q", c.Message)
	}
	if string(c.Raw) != string(raw) {
		t.Fatalf("Raw not preserved")
	}
}

func TestCommitNoParentsNoMessage(t *testing.T) {
	raw := BuildCommit(HashObject(ObjTree, nil), nil, "A <a@x> 1 +0000", "A <a@x> 1 +0000", "")
	c, err := ParseCommit(raw)
	if err != nil {
		t.Fatalf("ParseCommit: %v", err)
	}
	if len(c.Parents) != 0 || c.Message != "" {
		t.Fatalf("unexpected parents/message: %+v", c)
	}
}

func TestParseCommitMalformed(t *testing.T) {
	for _, bad := range [][]byte{
		nil,
		[]byte("not a commit"),
		[]byte("tree nothex\n\n"),
		[]byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nparent xyz\n\n"),
		[]byte("parent e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n\n"),
	} {
		if _, err := ParseCommit(bad); err == nil {
			t.Fatalf("ParseCommit(%q): expected error", bad)
		}
	}
}

func TestTreeSort(t *testing.T) {
	// git order: byte order of name, dirs as if suffixed with '/'.
	// "foo.txt" < "foo/" ('.' 0x2e < '/' 0x2f); "a-"/"ab" cases below.
	entries := []TreeEntry{
		{Mode: "40000", Name: "foo", SHA: HashObject(ObjTree, nil)},
		{Mode: "100644", Name: "foo.txt", SHA: HashObject(ObjBlob, []byte("x"))},
		{Mode: "100644", Name: "bar", SHA: HashObject(ObjBlob, []byte("y"))},
		{Mode: "40000", Name: "a", SHA: HashObject(ObjTree, nil)},
		{Mode: "100644", Name: "a-", SHA: HashObject(ObjBlob, []byte("z"))},
		{Mode: "100644", Name: "ab", SHA: HashObject(ObjBlob, []byte("w"))},
	}
	SortTreeEntries(entries)
	got := make([]string, len(entries))
	for i, e := range entries {
		got[i] = e.Name + "|" + e.Mode
	}
	// a- ("a-" < "a/": '-' < '/'), a/ ("a/" < "ab": '/' < 'b'), ab, bar,
	// foo.txt ('.' < '/'), foo/ .
	want := []string{"a-|100644", "a|40000", "ab|100644", "bar|100644", "foo.txt|100644", "foo|40000"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted order: got %v, want %v", got, want)
		}
	}
}

func TestTreeRoundTrip(t *testing.T) {
	blob := HashObject(ObjBlob, []byte("content"))
	sub := HashObject(ObjTree, nil)
	entries := []TreeEntry{
		{Mode: "100644", Name: "b.txt", SHA: blob},
		{Mode: "40000", Name: "a", SHA: sub},
		{Mode: "100755", Name: "run.sh", SHA: blob},
	}
	raw := BuildTree(entries)
	parsed, err := ParseTree(raw)
	if err != nil {
		t.Fatalf("ParseTree: %v", err)
	}
	if len(parsed) != 3 {
		t.Fatalf("parsed %d entries, want 3", len(parsed))
	}
	// BuildTree sorts: a/ first ("a/" < "b.txt"), then b.txt, run.sh.
	if parsed[0].Name != "a" || parsed[0].Mode != "40000" || parsed[0].SHA != sub {
		t.Fatalf("entry 0: %+v", parsed[0])
	}
	if parsed[1].Name != "b.txt" || parsed[1].SHA != blob {
		t.Fatalf("entry 1: %+v", parsed[1])
	}
	if parsed[2].Name != "run.sh" || parsed[2].Mode != "100755" {
		t.Fatalf("entry 2: %+v", parsed[2])
	}
	// Re-serializing the parsed entries reproduces the bytes.
	if string(BuildTree(parsed)) != string(raw) {
		t.Fatalf("BuildTree(ParseTree(x)) != x")
	}
}

func TestParseTreeMalformed(t *testing.T) {
	for _, bad := range [][]byte{
		[]byte("100644 no-nul"),
		[]byte("100644 x\x00short"),
		[]byte("noname"),
	} {
		if _, err := ParseTree(bad); err == nil {
			t.Fatalf("ParseTree(%q): expected error", bad)
		}
	}
	if _, err := ParseTree(nil); err != nil {
		t.Fatalf("ParseTree(empty): %v", err)
	}
}

func TestTagParse(t *testing.T) {
	target := HashObject(ObjCommit, []byte("c"))
	raw := []byte("object " + target + "\ntype commit\ntag v1\ntagger T <t@x> 1700000000 +0000\n\nrelease\n")
	tag, err := ParseTag(raw)
	if err != nil {
		t.Fatalf("ParseTag: %v", err)
	}
	if tag.Object != target || tag.Type != ObjCommit || tag.Tag != "v1" || tag.Message != "release\n" {
		t.Fatalf("tag: %+v", tag)
	}
	if TagTarget(raw) != target {
		t.Fatalf("TagTarget mismatch")
	}
	if TagTarget([]byte("garbage")) != "" {
		t.Fatalf("TagTarget(garbage) should be empty")
	}
}

func TestIsOID(t *testing.T) {
	if !IsOID("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391") {
		t.Fatalf("valid oid rejected")
	}
	for _, bad := range []string{"", "e69de29bb2d1d6434b8b29ae775ad8c2e48c539", "E69DE29BB2D1D6434B8B29AE775AD8C2E48C5391", "g69de29bb2d1d6434b8b29ae775ad8c2e48c5391", ZeroOID + "0"} {
		if IsOID(bad) {
			t.Fatalf("IsOID(%q) should be false", bad)
		}
	}
}
