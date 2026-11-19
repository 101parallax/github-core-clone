// End-to-end tests for the git smart-HTTP surface, driving handleGit
// directly with transport.Request values shaped exactly like the kit's
// git-client.ts sends them (paths with the .git suffix, the
// Git-Protocol header, pkt-line bodies). Response bytes are parsed
// with the same strictness the client applies.
package httpapi

import (
	"bytes"
	"strings"
	"testing"

	"forge/internal/git"
	"forge/internal/store"
	"forge/internal/transport"
)

// testServer builds a server over a fresh store with one repo.
func testServer(t *testing.T, repoName string) (*Server, *store.Store) {
	t.Helper()
	st := store.NewStore()
	if _, err := st.CreateRepo("adaiversen", repoName, store.RepoOptions{}); err != nil {
		t.Fatalf("CreateRepo: %v", err)
	}
	return NewServer(st), st
}

func gitReq(method, path, query string, headers map[string]string, body []byte) *transport.Request {
	return &transport.Request{Method: method, Path: path, Query: query, Headers: headers, Body: body}
}

func v2Headers() map[string]string { return map[string]string{"git-protocol": "version=2"} }

// pktLines encodes strings/control markers into a pkt-line body.
// "flush" and "delim" are control packets; anything else is a data packet.
func pktLines(items ...string) []byte {
	var out []byte
	for _, item := range items {
		switch item {
		case "flush":
			out = git.AppendPktFlush(out)
		case "delim":
			out = git.AppendPktDelim(out)
		default:
			out = git.EncodePktLineString(out, item)
		}
	}
	return out
}

// decodeDataLines decodes a response body into its data-packet lines
// (control packets dropped), failing the test on malformed framing.
func decodeDataLines(t *testing.T, body []byte) []string {
	t.Helper()
	dec := git.NewPktDecoder(body)
	var lines []string
	for !dec.Exhausted() {
		kind, payload, err := dec.Next()
		if err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if kind == git.PktData {
			lines = append(lines, string(payload))
		}
	}
	return lines
}

// fetchV2Body builds a v2 fetch request body.
func fetchV2Body(wants, haves, shallow []string, depth int) []byte {
	items := []string{"command=fetch\n", "object-format=sha1\n", "delim", "thin-pack\n", "no-progress\n", "ofs-delta\n"}
	for _, w := range wants {
		items = append(items, "want "+w+"\n")
	}
	for _, h := range haves {
		items = append(items, "have "+h+"\n")
	}
	for _, s := range shallow {
		items = append(items, "shallow "+s+"\n")
	}
	if depth > 0 {
		items = append(items, "deepen "+itoa(depth)+"\n")
	}
	items = append(items, "done\n", "flush")
	return pktLines(items...)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// pushBody builds a receive-pack request body: command list + flush +
// pack bytes. caps go on the first command line after a NUL.
func pushBody(t *testing.T, commands [][3]string, objects []git.Object) []byte {
	t.Helper()
	var items []string
	for i, cmd := range commands {
		line := cmd[0] + " " + cmd[1] + " " + cmd[2]
		if i == 0 {
			line += "\x00report-status side-band-64k ofs-delta"
		}
		items = append(items, line+"\n")
	}
	items = append(items, "flush")
	body := pktLines(items...)
	updates := false
	for _, cmd := range commands {
		if cmd[1] != git.ZeroOID {
			updates = true
		}
	}
	if updates {
		body = append(body, git.BuildPack(objects)...)
	}
	return body
}

// parsePushReport demuxes a sideband-wrapped report-status body into
// its text lines.
func parsePushReport(t *testing.T, body []byte) []string {
	t.Helper()
	// Outer framing: sideband packets (band 1 = report bytes).
	dec := git.NewPktDecoder(body)
	var inner []byte
	for !dec.Exhausted() {
		kind, payload, err := dec.Next()
		if err != nil {
			t.Fatalf("decode report framing: %v", err)
		}
		if kind != git.PktData {
			continue
		}
		if len(payload) < 1 || payload[0] != 1 {
			t.Fatalf("report packet has band %d, want 1", payload[0])
		}
		inner = append(inner, payload[1:]...)
	}
	return decodeDataLines(t, inner)
}

// fetchResult is a parsed v2 fetch response.
type fetchResult struct {
	acks      []string
	nak       bool
	ready     bool
	shallow   []string
	unshallow []string
	pack      []byte
}

// parseFetchV2 parses a v2 fetch response body, enforcing the section
// grammar the client enforces.
func parseFetchV2(t *testing.T, body []byte) fetchResult {
	t.Helper()
	var res fetchResult
	dec := git.NewPktDecoder(body)
	section := ""
	for !dec.Exhausted() {
		kind, payload, err := dec.Next()
		if err != nil {
			t.Fatalf("decode fetch: %v", err)
		}
		if kind == git.PktFlush || kind == git.PktDelim {
			section = ""
			continue
		}
		if kind != git.PktData {
			t.Fatalf("unexpected control packet in fetch")
		}
		if section == "" {
			switch string(payload) {
			case "acknowledgments\n":
				section = "ack"
			case "shallow-info\n":
				section = "shallow"
			case "packfile\n":
				section = "pack"
			default:
				t.Fatalf("unexpected fetch section %q", payload)
			}
			continue
		}
		switch section {
		case "ack":
			line := strings.TrimSuffix(string(payload), "\n")
			switch {
			case line == "NAK":
				res.nak = true
			case line == "ready":
				res.ready = true
			case strings.HasPrefix(line, "ACK "):
				res.acks = append(res.acks, line[4:])
			default:
				t.Fatalf("bad ack line %q", line)
			}
		case "shallow":
			line := strings.TrimSuffix(string(payload), "\n")
			switch {
			case strings.HasPrefix(line, "shallow "):
				res.shallow = append(res.shallow, line[8:])
			case strings.HasPrefix(line, "unshallow "):
				res.unshallow = append(res.unshallow, line[10:])
			default:
				t.Fatalf("bad shallow-info line %q", line)
			}
		case "pack":
			if len(payload) < 1 {
				t.Fatalf("empty sideband packet")
			}
			switch payload[0] {
			case 1:
				res.pack = append(res.pack, payload[1:]...)
			case 3:
				t.Fatalf("server sideband error: %s", payload[1:])
			default:
				t.Fatalf("bad sideband band %d", payload[0])
			}
		}
	}
	return res
}

// commitChain builds n commits in a chain in the store's object space
// (returned as objects + tips); it does not touch refs.
func commitChain(t *testing.T, n int) ([]git.Object, []string) {
	t.Helper()
	var objs []git.Object
	var tips []string
	parent := ""
	for i := 0; i < n; i++ {
		blob := []byte("content revision " + itoa(i) + "\n")
		blobOID := git.HashObject(git.ObjBlob, blob)
		tree := git.BuildTree([]git.TreeEntry{{Mode: "100644", Name: "f.txt", SHA: blobOID}})
		treeOID := git.HashObject(git.ObjTree, tree)
		var parents []string
		if parent != "" {
			parents = []string{parent}
		}
		commit := git.BuildCommit(treeOID, parents, "A <a@x> 1700000000 +0000", "A <a@x> 1700000000 +0000", "commit "+itoa(i)+"\n")
		commitOID := git.HashObject(git.ObjCommit, commit)
		objs = append(objs,
			git.Object{SHA: blobOID, Type: git.ObjBlob, Data: blob},
			git.Object{SHA: treeOID, Type: git.ObjTree, Data: tree},
			git.Object{SHA: commitOID, Type: git.ObjCommit, Data: commit},
		)
		tips = append(tips, commitOID)
		parent = commitOID
	}
	return objs, tips
}

// doPush pushes commands and returns the parsed report lines.
func doPush(t *testing.T, srv *Server, repo string, commands [][3]string, objects []git.Object) []string {
	t.Helper()
	resp := srv.handleGit(gitReq("POST", "/adaiversen/"+repo+".git/git-receive-pack", "", nil, pushBody(t, commands, objects)))
	if resp.Status != 200 {
		t.Fatalf("push status %d", resp.Status)
	}
	if ct := resp.Headers["Content-Type"]; ct != "application/x-git-receive-pack-result" {
		t.Fatalf("push content-type %q", ct)
	}
	return parsePushReport(t, resp.Body)
}

func TestGitInfoRefsV2(t *testing.T) {
	srv, _ := testServer(t, "e2e-adv-v2")
	resp := srv.handleGit(gitReq("GET", "/adaiversen/e2e-adv-v2.git/info/refs", "service=git-upload-pack", v2Headers(), nil))
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	if ct := resp.Headers["Content-Type"]; ct != "application/x-git-upload-pack-advertisement" {
		t.Fatalf("content-type %q", ct)
	}
	lines := decodeDataLines(t, resp.Body)
	if len(lines) < 2 || lines[0] != "# service=git-upload-pack\n" || lines[1] != "version 2\n" {
		t.Fatalf("v2 advert lines: %q", lines)
	}
	joined := strings.Join(lines, "")
	if !strings.Contains(joined, "fetch=shallow") || !strings.Contains(joined, "ls-refs=unborn") {
		t.Fatalf("v2 advert missing capabilities: %q", lines)
	}
}

func TestGitInfoRefsV0AndReceive(t *testing.T) {
	srv, _ := testServer(t, "e2e-adv-v0")
	objs, tips := commitChain(t, 2)
	report := doPush(t, srv, "e2e-adv-v0", [][3]string{{git.ZeroOID, tips[1], "refs/heads/main"}}, objs)
	if report[0] != "unpack ok\n" || report[1] != "ok refs/heads/main\n" {
		t.Fatalf("setup push report: %q", report)
	}
	// v0 upload-pack: no Git-Protocol header.
	resp := srv.handleGit(gitReq("GET", "/adaiversen/e2e-adv-v0.git/info/refs", "service=git-upload-pack", nil, nil))
	if resp.Status != 200 {
		t.Fatalf("status %d", resp.Status)
	}
	lines := decodeDataLines(t, resp.Body)
	if lines[0] != "# service=git-upload-pack\n" {
		t.Fatalf("v0 preamble: %q", lines[0])
	}
	joined := strings.Join(lines, "")
	if !strings.Contains(joined, "side-band-64k") || !strings.Contains(joined, "symref=HEAD:refs/heads/main") {
		t.Fatalf("v0 upload caps: %q", lines)
	}
	if !strings.Contains(joined, tips[1]+" refs/heads/main\n") {
		t.Fatalf("v0 refs: %q", lines)
	}
	// Receive-pack advert must carry the push capabilities.
	resp = srv.handleGit(gitReq("GET", "/adaiversen/e2e-adv-v0.git/info/refs", "service=git-receive-pack", nil, nil))
	lines = decodeDataLines(t, resp.Body)
	if lines[0] != "# service=git-receive-pack\n" {
		t.Fatalf("receive preamble: %q", lines[0])
	}
	joined = strings.Join(lines, "")
	for _, cap := range []string{"report-status", "side-band-64k", "delete-refs"} {
		if !strings.Contains(joined, cap) {
			t.Fatalf("receive caps missing %s: %q", cap, lines)
		}
	}
}

func TestGitInfoRefsEmptyRepo(t *testing.T) {
	srv, _ := testServer(t, "e2e-adv-empty")
	resp := srv.handleGit(gitReq("GET", "/adaiversen/e2e-adv-empty.git/info/refs", "service=git-upload-pack", nil, nil))
	lines := decodeDataLines(t, resp.Body)
	if len(lines) != 2 || !strings.Contains(lines[1], "capabilities^{}") {
		t.Fatalf("empty repo v0 advert: %q", lines)
	}
}

func TestGitUnknownRepo404(t *testing.T) {
	srv, _ := testServer(t, "e2e-404")
	resp := srv.handleGit(gitReq("GET", "/adaiversen/nope.git/info/refs", "service=git-upload-pack", v2Headers(), nil))
	if resp.Status != 404 {
		t.Fatalf("unknown repo info/refs: status %d, want 404", resp.Status)
	}
	resp = srv.handleGit(gitReq("POST", "/adaiversen/nope.git/git-upload-pack", "", nil, pktLines("command=ls-refs\n", "delim", "flush")))
	if resp.Status != 404 {
		t.Fatalf("unknown repo upload-pack: status %d, want 404", resp.Status)
	}
	// The server stays healthy afterwards.
	resp = srv.handleGit(gitReq("GET", "/adaiversen/e2e-404.git/info/refs", "service=git-upload-pack", v2Headers(), nil))
	if resp.Status != 200 {
		t.Fatalf("known repo after 404: status %d", resp.Status)
	}
}

func TestGitLsRefs(t *testing.T) {
	srv, _ := testServer(t, "e2e-lsrefs")
	objs, tips := commitChain(t, 2)
	tagData := []byte("object " + tips[1] + "\ntype commit\ntag v1\ntagger A <a@x> 1700000000 +0000\n\nv1\n")
	tagOID := git.HashObject(git.ObjTag, tagData)
	objs = append(objs, git.Object{SHA: tagOID, Type: git.ObjTag, Data: tagData})
	report := doPush(t, srv, "e2e-lsrefs", [][3]string{
		{git.ZeroOID, tips[1], "refs/heads/main"},
		{git.ZeroOID, tagOID, "refs/tags/v1"},
	}, objs)
	if len(report) != 3 || report[1] != "ok refs/heads/main\n" || report[2] != "ok refs/tags/v1\n" {
		t.Fatalf("setup push report: %q", report)
	}
	lsRefs := func(args ...string) []string {
		items := []string{"command=ls-refs\n", "object-format=sha1\n", "delim"}
		items = append(items, args...)
		items = append(items, "flush")
		resp := srv.handleGit(gitReq("POST", "/adaiversen/e2e-lsrefs.git/git-upload-pack", "", v2Headers(), pktLines(items...)))
		if resp.Status != 200 {
			t.Fatalf("ls-refs status %d", resp.Status)
		}
		if ct := resp.Headers["Content-Type"]; ct != "application/x-git-upload-pack-result" {
			t.Fatalf("ls-refs content-type %q", ct)
		}
		return decodeDataLines(t, resp.Body)
	}
	lines := lsRefs("peel\n", "symrefs\n", "unborn\n")
	joined := strings.Join(lines, "")
	if !strings.Contains(joined, tips[1]+" refs/heads/main\n") {
		t.Fatalf("ls-refs missing main: %q", lines)
	}
	if !strings.Contains(joined, "HEAD symref-target:refs/heads/main\n") {
		t.Fatalf("ls-refs missing HEAD symref: %q", lines)
	}
	if !strings.Contains(joined, tagOID+" refs/tags/v1 peeled:"+tips[1]+"\n") {
		t.Fatalf("ls-refs missing peeled tag: %q", lines)
	}
	// Prefix filtering is server-side.
	heads := lsRefs("peel\n", "symrefs\n", "ref-prefix refs/heads/\n")
	for _, l := range heads {
		if !strings.Contains(l, "refs/heads/") {
			t.Fatalf("heads prefix leaked %q", l)
		}
	}
	if len(heads) != 1 {
		t.Fatalf("heads prefix: %d lines, want 1", len(heads))
	}
	none := lsRefs("ref-prefix refs/does-not-exist/\n")
	if len(none) != 0 {
		t.Fatalf("unmatched prefix: %d lines, want 0", len(none))
	}
}

func TestGitLsRefsUnborn(t *testing.T) {
	srv, _ := testServer(t, "e2e-lsrefs-unborn")
	items := []string{"command=ls-refs\n", "delim", "peel\n", "symrefs\n", "unborn\n", "flush"}
	resp := srv.handleGit(gitReq("POST", "/adaiversen/e2e-lsrefs-unborn.git/git-upload-pack", "", v2Headers(), pktLines(items...)))
	lines := decodeDataLines(t, resp.Body)
	if len(lines) != 1 || lines[0] != "unborn HEAD symref-target:refs/heads/main\n" {
		t.Fatalf("unborn ls-refs: %q", lines)
	}
	// Without unborn requested: no refs at all.
	items = []string{"command=ls-refs\n", "delim", "peel\n", "symrefs\n", "flush"}
	resp = srv.handleGit(gitReq("POST", "/adaiversen/e2e-lsrefs-unborn.git/git-upload-pack", "", v2Headers(), pktLines(items...)))
	lines = decodeDataLines(t, resp.Body)
	if len(lines) != 0 {
		t.Fatalf("unborn ls-refs without unborn: %q", lines)
	}
}

func TestGitCloneRoundTrip(t *testing.T) {
	srv, _ := testServer(t, "e2e-clone")
	objs, tips := commitChain(t, 3)
	report := doPush(t, srv, "e2e-clone", [][3]string{{git.ZeroOID, tips[2], "refs/heads/main"}}, objs)
	if report[1] != "ok refs/heads/main\n" {
		t.Fatalf("setup push: %q", report)
	}
	resp := srv.handleGit(gitReq("POST", "/adaiversen/e2e-clone.git/git-upload-pack", "", v2Headers(), fetchV2Body([]string{tips[2]}, nil, nil, 0)))
	if resp.Status != 200 {
		t.Fatalf("fetch status %d", resp.Status)
	}
	fetched := parseFetchV2(t, resp.Body)
	if fetched.nak || len(fetched.acks) != 0 {
		t.Fatalf("full fetch acks: %+v", fetched)
	}
	got, err := git.ReadPack(fetched.pack, nil)
	if err != nil {
		t.Fatalf("ReadPack(fetched): %v", err)
	}
	if len(got) != len(objs) {
		t.Fatalf("cloned %d objects, want %d", len(got), len(objs))
	}
	want := make(map[string]git.Object, len(objs))
	for _, o := range objs {
		want[o.SHA] = o
	}
	for _, o := range got {
		w, ok := want[o.SHA]
		if !ok || w.Type != o.Type || !bytes.Equal(w.Data, o.Data) {
			t.Fatalf("cloned object %s mismatch", o.SHA)
		}
	}
	// A second identical fetch is byte-identical (whole-response cache).
	resp2 := srv.handleGit(gitReq("POST", "/adaiversen/e2e-clone.git/git-upload-pack", "", v2Headers(), fetchV2Body([]string{tips[2]}, nil, nil, 0)))
	if !bytes.Equal(resp.Body, resp2.Body) {
		t.Fatalf("repeated fetch bytes differ (cache incoherence)")
	}
}

func TestGitShallowCloneAndDeepen(t *testing.T) {
	srv, _ := testServer(t, "e2e-shallow")
	objs, tips := commitChain(t, 3)
	doPush(t, srv, "e2e-shallow", [][3]string{{git.ZeroOID, tips[2], "refs/heads/main"}}, objs)
	fetch := func(wants, haves, shallow []string, depth int) fetchResult {
		resp := srv.handleGit(gitReq("POST", "/adaiversen/e2e-shallow.git/git-upload-pack", "", v2Headers(), fetchV2Body(wants, haves, shallow, depth)))
		if resp.Status != 200 {
			t.Fatalf("fetch status %d", resp.Status)
		}
		return parseFetchV2(t, resp.Body)
	}
	shallow := fetch([]string{tips[2]}, nil, nil, 1)
	if len(shallow.shallow) != 1 || shallow.shallow[0] != tips[2] {
		t.Fatalf("depth-1 shallow-info: %v", shallow.shallow)
	}
	got, err := git.ReadPack(shallow.pack, nil)
	if err != nil {
		t.Fatalf("ReadPack: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("depth-1 pack: %d objects, want 3", len(got))
	}
	deepened := fetch([]string{tips[2]}, []string{tips[2]}, []string{tips[2]}, 2)
	if len(deepened.shallow) != 1 || deepened.shallow[0] != tips[1] {
		t.Fatalf("deepen shallow: %v", deepened.shallow)
	}
	if len(deepened.unshallow) != 1 || deepened.unshallow[0] != tips[2] {
		t.Fatalf("deepen unshallow: %v", deepened.unshallow)
	}
	got, err = git.ReadPack(deepened.pack, nil)
	if err != nil {
		t.Fatalf("ReadPack(deepened): %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("deepened pack: %d objects, want 3", len(got))
	}
	// Nothing-new: an empty pack, still with a packfile section.
	none := fetch([]string{tips[2]}, []string{tips[2]}, nil, 0)
	if len(none.pack) != 32 {
		t.Fatalf("nothing-new pack: %d bytes, want 32 (empty pack)", len(none.pack))
	}
	got, err = git.ReadPack(none.pack, nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("nothing-new pack parse: %d objects err=%v", len(got), err)
	}
}

func TestGitPushNonFastForwardAndMixed(t *testing.T) {
	srv, _ := testServer(t, "e2e-nff")
	objs, tips := commitChain(t, 2)
	doPush(t, srv, "e2e-nff", [][3]string{{git.ZeroOID, tips[1], "refs/heads/main"}}, objs)
	// Sibling commit off tips[0]: not a descendant of tips[1].
	blob := []byte("sibling\n")
	blobOID := git.HashObject(git.ObjBlob, blob)
	tree := git.BuildTree([]git.TreeEntry{{Mode: "100644", Name: "f.txt", SHA: blobOID}})
	treeOID := git.HashObject(git.ObjTree, tree)
	sibling := git.BuildCommit(treeOID, []string{tips[0]}, "A <a@x> 1700000000 +0000", "A <a@x> 1700000000 +0000", "sibling\n")
	siblingOID := git.HashObject(git.ObjCommit, sibling)
	sibObjs := []git.Object{
		{SHA: blobOID, Type: git.ObjBlob, Data: blob},
		{SHA: treeOID, Type: git.ObjTree, Data: tree},
		{SHA: siblingOID, Type: git.ObjCommit, Data: sibling},
	}
	report := doPush(t, srv, "e2e-nff", [][3]string{{tips[1], siblingOID, "refs/heads/main"}}, sibObjs)
	if len(report) != 2 || report[0] != "unpack ok\n" || report[1] != "ng refs/heads/main non-fast-forward\n" {
		t.Fatalf("non-FF report: %q", report)
	}
	// The ref did not move.
	resp := srv.handleGit(gitReq("GET", "/adaiversen/e2e-nff.git/info/refs", "service=git-upload-pack", nil, nil))
	if !strings.Contains(strings.Join(decodeDataLines(t, resp.Body), ""), tips[1]+" refs/heads/main\n") {
		t.Fatalf("ref moved after refused push")
	}
	// Mixed: one FF advance + one non-FF in a single push.
	fwd := append([]git.Object(nil), objs...)
	report = doPush(t, srv, "e2e-nff", [][3]string{
		{git.ZeroOID, tips[1], "refs/heads/side"},
	}, fwd)
	if report[1] != "ok refs/heads/side\n" {
		t.Fatalf("side create: %q", report)
	}
	// Advance main by pushing a child of tips[1]; refuse side's sibling.
	childBlob := []byte("child\n")
	childBlobOID := git.HashObject(git.ObjBlob, childBlob)
	childTree := git.BuildTree([]git.TreeEntry{{Mode: "100644", Name: "f.txt", SHA: childBlobOID}})
	childTreeOID := git.HashObject(git.ObjTree, childTree)
	child := git.BuildCommit(childTreeOID, []string{tips[1]}, "A <a@x> 1700000000 +0000", "A <a@x> 1700000000 +0000", "child\n")
	childOID := git.HashObject(git.ObjCommit, child)
	mixedObjs := append(sibObjs,
		git.Object{SHA: childBlobOID, Type: git.ObjBlob, Data: childBlob},
		git.Object{SHA: childTreeOID, Type: git.ObjTree, Data: childTree},
		git.Object{SHA: childOID, Type: git.ObjCommit, Data: child},
	)
	report = doPush(t, srv, "e2e-nff", [][3]string{
		{tips[1], childOID, "refs/heads/main"},
		{tips[1], siblingOID, "refs/heads/side"},
	}, mixedObjs)
	if len(report) != 3 || report[1] != "ok refs/heads/main\n" || report[2] != "ng refs/heads/side non-fast-forward\n" {
		t.Fatalf("mixed report: %q", report)
	}
}

func TestGitPushDelete(t *testing.T) {
	srv, _ := testServer(t, "e2e-delete")
	objs, tips := commitChain(t, 1)
	doPush(t, srv, "e2e-delete", [][3]string{
		{git.ZeroOID, tips[0], "refs/heads/main"},
		{git.ZeroOID, tips[0], "refs/heads/feature"},
	}, objs)
	// Delete-only push carries no pack.
	report := doPush(t, srv, "e2e-delete", [][3]string{{tips[0], git.ZeroOID, "refs/heads/feature"}}, nil)
	if len(report) != 2 || report[0] != "unpack ok\n" || report[1] != "ok refs/heads/feature\n" {
		t.Fatalf("delete report: %q", report)
	}
	resp := srv.handleGit(gitReq("GET", "/adaiversen/e2e-delete.git/info/refs", "service=git-upload-pack", nil, nil))
	joined := strings.Join(decodeDataLines(t, resp.Body), "")
	if strings.Contains(joined, "refs/heads/feature") {
		t.Fatalf("deleted ref still advertised")
	}
	if !strings.Contains(joined, tips[0]+" refs/heads/main\n") {
		t.Fatalf("main damaged by delete")
	}
}

func TestGitMalformedSurvives(t *testing.T) {
	srv, _ := testServer(t, "e2e-malformed")
	objs, tips := commitChain(t, 1)
	doPush(t, srv, "e2e-malformed", [][3]string{{git.ZeroOID, tips[0], "refs/heads/main"}}, objs)
	resp := srv.handleGit(gitReq("POST", "/adaiversen/e2e-malformed.git/git-upload-pack", "", nil, []byte("zzzznot-a-pkt-line")))
	if resp.Status != 400 {
		t.Fatalf("malformed POST: status %d, want 400", resp.Status)
	}
	// Server still healthy and the repo intact.
	resp = srv.handleGit(gitReq("GET", "/adaiversen/e2e-malformed.git/info/refs", "service=git-upload-pack", v2Headers(), nil))
	if resp.Status != 200 {
		t.Fatalf("healthy check after malformed: status %d", resp.Status)
	}
	resp = srv.handleGit(gitReq("POST", "/adaiversen/e2e-malformed.git/git-upload-pack", "", v2Headers(), fetchV2Body([]string{tips[0]}, nil, nil, 0)))
	if resp.Status != 200 {
		t.Fatalf("fetch after malformed: status %d", resp.Status)
	}
}

func TestGitV0Fetch(t *testing.T) {
	srv, _ := testServer(t, "e2e-v0fetch")
	objs, tips := commitChain(t, 2)
	doPush(t, srv, "e2e-v0fetch", [][3]string{{git.ZeroOID, tips[1], "refs/heads/main"}}, objs)
	// v0 fetch: wants section + flush, haves section + flush.
	body := pktLines(
		"want "+tips[1]+" side-band-64k thin-pack ofs-delta\n",
		"flush",
		"have "+tips[0]+"\n",
		"done\n",
		"flush",
	)
	resp := srv.handleGit(gitReq("POST", "/adaiversen/e2e-v0fetch.git/git-upload-pack", "", nil, body))
	if resp.Status != 200 {
		t.Fatalf("v0 fetch status %d", resp.Status)
	}
	// Parse: text lines (ACK) then sideband pack packets.
	dec := git.NewPktDecoder(resp.Body)
	var pack []byte
	sawACK := false
	for !dec.Exhausted() {
		kind, payload, err := dec.Next()
		if err != nil {
			t.Fatalf("decode v0 fetch: %v", err)
		}
		if kind != git.PktData {
			continue
		}
		if len(payload) > 0 && (payload[0] == 1 || payload[0] == 2 || payload[0] == 3) {
			if payload[0] == 3 {
				t.Fatalf("v0 sideband error: %s", payload[1:])
			}
			if payload[0] == 1 {
				pack = append(pack, payload[1:]...)
			}
			continue
		}
		if strings.HasPrefix(string(payload), "ACK ") {
			sawACK = true
		}
	}
	if !sawACK {
		t.Fatalf("v0 fetch sent no ACK for the held ancestor")
	}
	got, err := git.ReadPack(pack, nil)
	if err != nil {
		t.Fatalf("ReadPack(v0): %v", err)
	}
	// Only the new objects: tips[1] commit + tree + blob = 3.
	if len(got) != 3 {
		t.Fatalf("v0 fetch pack: %d objects, want 3", len(got))
	}
}

func TestGitCacheInvalidatedByPush(t *testing.T) {
	srv, _ := testServer(t, "e2e-cache-inv")
	objs, tips := commitChain(t, 1)
	doPush(t, srv, "e2e-cache-inv", [][3]string{{git.ZeroOID, tips[0], "refs/heads/main"}}, objs)
	fetchOnce := func() []byte {
		resp := srv.handleGit(gitReq("POST", "/adaiversen/e2e-cache-inv.git/git-upload-pack", "", v2Headers(), fetchV2Body([]string{tips[0]}, nil, nil, 0)))
		if resp.Status != 200 {
			t.Fatalf("fetch status %d", resp.Status)
		}
		return resp.Body
	}
	first := fetchOnce()
	// Push a second commit: the generation bumps, so the cached
	// advertisement must refresh (and the old fetch key stays valid
	// because its wants are unchanged — same bytes expected).
	// Build a child of tips[0] directly.
	blob := []byte("second\n")
	blobOID := git.HashObject(git.ObjBlob, blob)
	tree := git.BuildTree([]git.TreeEntry{{Mode: "100644", Name: "f.txt", SHA: blobOID}})
	treeOID := git.HashObject(git.ObjTree, tree)
	child := git.BuildCommit(treeOID, []string{tips[0]}, "A <a@x> 1700000000 +0000", "A <a@x> 1700000000 +0000", "second\n")
	childOID := git.HashObject(git.ObjCommit, child)
	childObjs := []git.Object{
		{SHA: blobOID, Type: git.ObjBlob, Data: blob},
		{SHA: treeOID, Type: git.ObjTree, Data: tree},
		{SHA: childOID, Type: git.ObjCommit, Data: child},
	}
	doPush(t, srv, "e2e-cache-inv", [][3]string{{tips[0], childOID, "refs/heads/main"}}, childObjs)
	// Same-want fetch: same bytes (objects are immutable).
	if second := fetchOnce(); !bytes.Equal(first, second) {
		t.Fatalf("same-want fetch changed after an unrelated push")
	}
	// The v0 advertisement must show the NEW tip (gen-keyed cache).
	resp := srv.handleGit(gitReq("GET", "/adaiversen/e2e-cache-inv.git/info/refs", "service=git-upload-pack", nil, nil))
	if !strings.Contains(strings.Join(decodeDataLines(t, resp.Body), ""), childOID+" refs/heads/main\n") {
		t.Fatalf("advertisement stale after push")
	}
	// ls-refs must show the new tip too.
	lsResp := srv.handleGit(gitReq("POST", "/adaiversen/e2e-cache-inv.git/git-upload-pack", "", v2Headers(),
		pktLines("command=ls-refs\n", "delim", "peel\n", "symrefs\n", "flush")))
	if !strings.Contains(strings.Join(decodeDataLines(t, lsResp.Body), ""), childOID+" refs/heads/main\n") {
		t.Fatalf("ls-refs stale after push")
	}
}
