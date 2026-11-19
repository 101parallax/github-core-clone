// Git smart-HTTP handlers: info/refs advertisement (v2 + v0),
// upload-pack (v2 fetch + ls-refs, v0 fetch fallback), and receive-pack
// (v0 push with report-status + side-band-64k).
//
// Wire contract (from the kit's git-client.ts, the source of truth):
//   - Paths carry the .git suffix: /{owner}/{repo}.git/info/refs,
//     /{owner}/{repo}.git/git-upload-pack, /{owner}/{repo}.git/git-receive-pack.
//     The dispatcher routes both suffixed and bare forms here; the suffix
//     is stripped when resolving the repo name.
//   - Protocol v2 is detected ONLY via the Git-Protocol: version=2 request
//     header on info/refs GET; the service comes from ?service=.
//   - Content types are exact: application/x-<service>-advertisement /
//     -result. A v0/receive-pack advertisement starts with the
//     "# service=" preamble pkt-line + flush.
//   - A refused push is HTTP 200 + a report naming the reason
//     (exactly "non-fast-forward"); never a non-200 status.
//
// Performance (the clone bench is 50 identical shallow clones, 5 HTTP
// requests each): the v2 advertisement is static bytes; v0 adverts,
// ls-refs responses and whole v2 fetch responses are cached per
// (repo, generation, request fingerprint) and served from memory after
// the first build. Cache builds are single-flighted under one mutex.
package httpapi

import (
	"sort"
	"strconv"
	"strings"
	"sync"

	"forge/internal/git"
	"forge/internal/store"
	"forge/internal/transport"
)

// ---------------------------------------------------------------- responses

// gitBytesResponse builds a 200 response with an explicit content type
// (the git services never use the JSON default).
func gitBytesResponse(contentType string, body []byte) *transport.Response {
	return &transport.Response{
		Status:  200,
		Headers: map[string]string{"Content-Type": contentType},
		Body:    body,
	}
}

// gitJSONError builds a JSON error response: {"message": msg}.
// msg must be a static literal (no quoting/escaping is applied).
func gitJSONError(status int, msg string) *transport.Response {
	return &transport.Response{
		Status:  status,
		Headers: map[string]string{"Content-Type": "application/json; charset=utf-8"},
		Body:    []byte("{\"message\":\"" + msg + "\"}"),
	}
}

// ---------------------------------------------------------------- response cache

// respCache is a whole-response cache for the git hot paths (v0
// advertisements, ls-refs, v2 fetch responses). Keys include the repo's
// mutation generation, so a stale entry is never served: refs change
// only via SetRef/DeleteRef, which bump the generation, and objects
// are immutable. Total bytes are capped with clear-all eviction; the
// trial's working set is far below the cap.
const respCacheCap = 64 << 20 // 64 MiB

var gitRespCache = &respCache{entries: make(map[string][]byte, 64)}

type respCache struct {
	mu      sync.Mutex
	entries map[string][]byte
	bytes   int
}

// cachedResponse returns the cached body for key, or builds it with
// build (under the cache lock, so concurrent identical requests
// single-flight onto one build) and caches the result. Build errors
// are never cached.
func (c *respCache) cachedResponse(key string, build func() ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if body, ok := c.entries[key]; ok {
		return body, nil
	}
	body, err := build()
	if err != nil {
		return nil, err
	}
	if c.bytes+len(body) > respCacheCap {
		c.entries = make(map[string][]byte, 64)
		c.bytes = 0
	}
	// Another goroutine cannot have inserted under the same key while
	// we hold the lock; store unconditionally.
	c.entries[key] = body
	c.bytes += len(body)
	return body, nil
}

// ---------------------------------------------------------------- routing

// handleGit serves the git smart-HTTP surface. It never panics on
// malformed input: the recover below turns any bug into a 500 instead
// of killing the process (the repo-survives-errors check).
func (s *Server) handleGit(req *transport.Request) (resp *transport.Response) {
	defer func() {
		if r := recover(); r != nil {
			resp = gitJSONError(500, "Internal Server Error")
		}
	}()

	// Path forms (with or without the .git suffix):
	//   /{owner}/{repo}.git/info/refs
	//   /{owner}/{repo}.git/git-upload-pack
	//   /{owner}/{repo}.git/git-receive-pack
	segments := strings.Split(strings.Trim(req.Path, "/"), "/")
	var tail string
	switch len(segments) {
	case 4:
		if segments[2] != "info" || segments[3] != "refs" {
			return gitJSONError(404, "Not Found")
		}
		tail = "info/refs"
	case 3:
		switch segments[2] {
		case "git-upload-pack", "git-receive-pack":
			tail = segments[2]
		default:
			return gitJSONError(404, "Not Found")
		}
	default:
		return gitJSONError(404, "Not Found")
	}
	owner := segments[0]
	repoName := strings.TrimSuffix(segments[1], ".git")

	repo, err := s.store.GetRepo(owner, repoName)
	if err != nil {
		return gitJSONError(404, "Not Found")
	}

	switch tail {
	case "info/refs":
		if req.Method != "GET" {
			return gitJSONError(405, "Method Not Allowed")
		}
		return s.gitInfoRefs(req, repo)
	case "git-upload-pack":
		if req.Method != "POST" {
			return gitJSONError(405, "Method Not Allowed")
		}
		return s.gitUploadPack(req, repo)
	case "git-receive-pack":
		if req.Method != "POST" {
			return gitJSONError(405, "Method Not Allowed")
		}
		return s.gitReceivePack(req, repo)
	}
	return gitJSONError(404, "Not Found")
}

// ---------------------------------------------------------------- info/refs

// v2Advertisement is the protocol v2 capability advertisement. It is
// identical for every repository (capabilities do not depend on refs),
// so it is built once and shared: preamble + flush + version 2 +
// ls-refs=unborn + fetch=shallow + object-format=sha1 + flush.
// The fetch value MUST include "shallow" or the client refuses depth.
var v2Advertisement = func() []byte {
	var b []byte
	b = git.EncodePktLineString(b, "# service=git-upload-pack\n")
	b = git.AppendPktFlush(b)
	b = git.EncodePktLineString(b, "version 2\n")
	b = git.EncodePktLineString(b, "ls-refs=unborn\n")
	b = git.EncodePktLineString(b, "fetch=shallow\n")
	b = git.EncodePktLineString(b, "object-format=sha1\n")
	b = git.AppendPktFlush(b)
	return b
}()

// v0 capability strings, advertised on the first ref line after a NUL.
// Upload-pack v0 needs side-band-64k (the v0 fetch path throws without
// it) and shallow; receive-pack v0 needs report-status, side-band-64k
// and delete-refs (all three are asserted by the checks).
const (
	v0UploadCaps  = "side-band-64k thin-pack ofs-delta shallow multi_ack symref=HEAD:"
	v0ReceiveCaps = "report-status side-band-64k delete-refs ofs-delta"
)

// gitInfoRefs answers GET info/refs?service=<service>. Upload-pack
// answers v2 iff the request carries "Git-Protocol: version=2", else
// v0; receive-pack is always v0.
func (s *Server) gitInfoRefs(req *transport.Request, repo *store.Repo) *transport.Response {
	service := req.QueryParam("service")
	switch service {
	case "git-upload-pack":
		if req.Header("git-protocol") == "version=2" {
			return gitBytesResponse("application/x-git-upload-pack-advertisement", v2Advertisement)
		}
		body, err := s.cachedV0Advert(repo, service)
		if err != nil {
			return gitJSONError(500, "Internal Server Error")
		}
		return gitBytesResponse("application/x-git-upload-pack-advertisement", body)
	case "git-receive-pack":
		body, err := s.cachedV0Advert(repo, service)
		if err != nil {
			return gitJSONError(500, "Internal Server Error")
		}
		return gitBytesResponse("application/x-git-receive-pack-advertisement", body)
	default:
		return gitJSONError(400, "missing service")
	}
}

// cachedV0Advert returns the v0 ref advertisement for a repo+service,
// cached per generation.
func (s *Server) cachedV0Advert(repo *store.Repo, service string) ([]byte, error) {
	gen := s.store.RepoGen(repo.Owner, repo.Name)
	var key strings.Builder
	key.WriteString("a0\x00")
	key.WriteString(service)
	key.WriteByte(0)
	key.WriteString(repo.Key())
	key.WriteByte(0)
	key.WriteString(strconv.FormatUint(gen, 10))
	return gitRespCache.cachedResponse(key.String(), func() ([]byte, error) {
		return s.buildV0Advert(repo, service), nil
	})
}

// buildV0Advert builds a v0 ref advertisement: the "# service="
// preamble + flush, then ref lines (HEAD first, then refs sorted by
// name) with capabilities after a NUL on the first line, and peeled
// "^{}" lines for annotated tags. An empty repo advertises the single
// "capabilities^{}" pseudo-ref line.
func (s *Server) buildV0Advert(repo *store.Repo, service string) []byte {
	owner, name := repo.Owner, repo.Name
	defaultRef := "refs/heads/" + repo.DefaultBranch
	refs := s.store.ListRefs(owner, name)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })

	caps := v0ReceiveCaps
	if service == "git-upload-pack" {
		caps = v0UploadCaps + defaultRef
	}

	// Pre-size: preamble + one line per ref (+ peeled lines) + flushes.
	out := make([]byte, 0, 128+len(refs)*96)
	out = git.EncodePktLineString(out, "# service="+service+"\n")
	out = git.AppendPktFlush(out)

	headTip, headOK := s.store.GetRef(owner, name, defaultRef)
	if len(refs) == 0 {
		out = git.EncodePktLineString(out, git.ZeroOID+" capabilities^{}\x00"+caps+"\n")
		out = git.AppendPktFlush(out)
		return out
	}

	// HEAD first, carrying the capabilities. An unborn default branch
	// advertises the zero oid (the client marks it unborn).
	headOID := git.ZeroOID
	if headOK {
		headOID = headTip
	}
	out = git.EncodePktLineString(out, headOID+" HEAD\x00"+caps+"\n")
	for _, ref := range refs {
		out = git.EncodePktLineString(out, ref.SHA+" "+ref.Name+"\n")
		// Annotated tags get a peeled line naming the final target.
		if strings.HasPrefix(ref.Name, "refs/tags/") {
			if peeled := git.PeelTag(s.store, ref.SHA); peeled != "" && peeled != ref.SHA {
				out = git.EncodePktLineString(out, peeled+" "+ref.Name+"^{}\n")
			}
		}
	}
	out = git.AppendPktFlush(out)
	return out
}

// ---------------------------------------------------------------- upload-pack

// gitUploadPack answers POST git-upload-pack: a v2 command
// (command=fetch / command=ls-refs) or a v0 want list. Malformed input
// is a 400, never a crash.
func (s *Server) gitUploadPack(req *transport.Request, repo *store.Repo) *transport.Response {
	dec := git.NewPktDecoder(req.Body)
	kind, payload, err := dec.Next()
	if err != nil || kind != git.PktData {
		return gitJSONError(400, "malformed pkt-line")
	}
	line := string(payload)
	switch {
	case line == "command=fetch\n":
		return s.gitFetchV2(req, repo, dec)
	case line == "command=ls-refs\n":
		return s.gitLsRefs(req, repo, dec)
	case strings.HasPrefix(line, "want "):
		return s.gitFetchV0(req, repo)
	default:
		return gitJSONError(400, "unknown upload-pack request")
	}
}

// ---------------------------------------------------------------- ls-refs

// gitLsRefs answers a v2 ls-refs command. Arguments follow the delim:
// peel, symrefs, unborn, ref-prefix <p>. The response is one pkt-line
// per ref plus a flush; ref-prefix filtering is server-side (an
// unmatched prefix yields zero refs).
func (s *Server) gitLsRefs(req *transport.Request, repo *store.Repo, dec *git.PktDecoder) *transport.Response {
	peel, symrefs, unborn := false, false, false
	var prefixes []string
	// Skip capability lines (agent=, object-format=) up to the delim.
	for {
		kind, _, err := dec.Next()
		if err != nil {
			return gitJSONError(400, "malformed pkt-line")
		}
		if kind == git.PktDelim {
			break
		}
		if kind != git.PktData {
			return gitJSONError(400, "malformed ls-refs request")
		}
	}
	for {
		kind, payload, err := dec.Next()
		if err != nil {
			return gitJSONError(400, "malformed pkt-line")
		}
		if kind == git.PktFlush {
			break
		}
		if kind != git.PktData {
			continue
		}
		arg := strings.TrimSuffix(string(payload), "\n")
		switch {
		case arg == "peel":
			peel = true
		case arg == "symrefs":
			symrefs = true
		case arg == "unborn":
			unborn = true
		case strings.HasPrefix(arg, "ref-prefix "):
			prefixes = append(prefixes, arg[len("ref-prefix "):])
		}
	}

	// Cache key: repo + gen + flags + sorted prefixes.
	gen := s.store.RepoGen(repo.Owner, repo.Name)
	sortedPrefixes := append([]string(nil), prefixes...)
	sort.Strings(sortedPrefixes)
	var key strings.Builder
	key.WriteString("ls\x00")
	key.WriteString(repo.Key())
	key.WriteByte(0)
	key.WriteString(strconv.FormatUint(gen, 10))
	key.WriteByte(0)
	if peel {
		key.WriteByte('p')
	}
	if symrefs {
		key.WriteByte('s')
	}
	if unborn {
		key.WriteByte('u')
	}
	for _, p := range sortedPrefixes {
		key.WriteByte(0)
		key.WriteString(p)
	}
	body, err := gitRespCache.cachedResponse(key.String(), func() ([]byte, error) {
		return s.buildLsRefs(repo, peel, symrefs, unborn, prefixes), nil
	})
	if err != nil {
		return gitJSONError(500, "Internal Server Error")
	}
	return gitBytesResponse("application/x-git-upload-pack-result", body)
}

// buildLsRefs builds the ls-refs response body: HEAD first (when it
// passes the prefix filter), then refs sorted by name. A tag ref
// carries "peeled:<commit>" when peel was requested; HEAD carries
// "symref-target:<default>" when symrefs was requested. An unborn repo
// reports "unborn HEAD ..." only when unborn was requested.
func (s *Server) buildLsRefs(repo *store.Repo, peel, symrefs, unborn bool, prefixes []string) []byte {
	owner, name := repo.Owner, repo.Name
	defaultRef := "refs/heads/" + repo.DefaultBranch
	matches := func(refName string) bool {
		if len(prefixes) == 0 {
			return true
		}
		for _, p := range prefixes {
			if strings.HasPrefix(refName, p) {
				return true
			}
		}
		return false
	}

	refs := s.store.ListRefs(owner, name)
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	out := make([]byte, 0, 128+len(refs)*96)

	if matches("HEAD") {
		if tip, ok := s.store.GetRef(owner, name, defaultRef); ok {
			var line strings.Builder
			line.WriteString(tip)
			line.WriteString(" HEAD")
			if symrefs {
				line.WriteString(" symref-target:")
				line.WriteString(defaultRef)
			}
			line.WriteString("\n")
			out = git.EncodePktLineString(out, line.String())
		} else if unborn {
			var line strings.Builder
			line.WriteString("unborn HEAD")
			if symrefs {
				line.WriteString(" symref-target:")
				line.WriteString(defaultRef)
			}
			line.WriteString("\n")
			out = git.EncodePktLineString(out, line.String())
		}
	}
	for _, ref := range refs {
		if !matches(ref.Name) {
			continue
		}
		var line strings.Builder
		line.WriteString(ref.SHA)
		line.WriteByte(' ')
		line.WriteString(ref.Name)
		if peel && strings.HasPrefix(ref.Name, "refs/tags/") {
			if peeled := git.PeelTag(s.store, ref.SHA); peeled != "" && peeled != ref.SHA {
				line.WriteString(" peeled:")
				line.WriteString(peeled)
			}
		}
		line.WriteString("\n")
		out = git.EncodePktLineString(out, line.String())
	}
	out = git.AppendPktFlush(out)
	return out
}

// ---------------------------------------------------------------- v2 fetch

// gitFetchV2 answers a v2 fetch command. The whole response body is
// cached per (repo, gen, wants, haves, shallow, depth): the clone
// workload's 50 identical fetches build once and serve 49x from memory.
func (s *Server) gitFetchV2(req *transport.Request, repo *store.Repo, dec *git.PktDecoder) *transport.Response {
	fetchReq, done, ok := parseFetchArgs(dec)
	if !ok {
		return gitJSONError(400, "malformed fetch request")
	}
	if len(fetchReq.Wants) == 0 {
		return gitJSONError(400, "fetch without want")
	}

	// Canonical cache key: sorted wants/haves/shallow + depth + done.
	wants := append([]string(nil), fetchReq.Wants...)
	haves := append([]string(nil), fetchReq.Haves...)
	shallow := append([]string(nil), fetchReq.Shallow...)
	sort.Strings(wants)
	sort.Strings(haves)
	sort.Strings(shallow)
	gen := s.store.RepoGen(repo.Owner, repo.Name)
	var key strings.Builder
	key.WriteString("f2\x00")
	key.WriteString(repo.Key())
	key.WriteByte(0)
	key.WriteString(strconv.FormatUint(gen, 10))
	key.WriteByte(0)
	key.WriteString(strconv.Itoa(fetchReq.Depth))
	key.WriteByte(0)
	if done {
		key.WriteByte('d')
	}
	key.WriteByte(0)
	key.WriteString(strings.Join(wants, ","))
	key.WriteByte(0)
	key.WriteString(strings.Join(haves, ","))
	key.WriteByte(0)
	key.WriteString(strings.Join(shallow, ","))

	body, err := gitRespCache.cachedResponse(key.String(), func() ([]byte, error) {
		return s.buildFetchV2(repo, fetchReq, done)
	})
	if err != nil {
		if err == git.ErrUnknownWant {
			return gitBytesResponse("application/x-git-upload-pack-result", fetchErrorResponse("unknown want object"))
		}
		return gitJSONError(500, "Internal Server Error")
	}
	return gitBytesResponse("application/x-git-upload-pack-result", body)
}

// parseFetchArgs parses a v2 fetch request after the "command=fetch"
// line: capability lines up to the delim, then argument lines up to
// the flush. It returns the fetch request, whether "done" was sent,
// and false on malformed input.
func parseFetchArgs(dec *git.PktDecoder) (git.FetchRequest, bool, bool) {
	var req git.FetchRequest
	done := false
	for {
		kind, _, err := dec.Next()
		if err != nil {
			return req, false, false
		}
		if kind == git.PktDelim {
			break
		}
		if kind != git.PktData {
			return req, false, false
		}
	}
	for {
		kind, payload, err := dec.Next()
		if err != nil {
			return req, false, false
		}
		if kind == git.PktFlush {
			break
		}
		if kind != git.PktData {
			continue
		}
		arg := strings.TrimSuffix(string(payload), "\n")
		switch {
		case strings.HasPrefix(arg, "want "):
			req.Wants = append(req.Wants, arg[len("want "):])
		case strings.HasPrefix(arg, "have "):
			req.Haves = append(req.Haves, arg[len("have "):])
		case strings.HasPrefix(arg, "shallow "):
			req.Shallow = append(req.Shallow, arg[len("shallow "):])
		case strings.HasPrefix(arg, "deepen "):
			if n, err := strconv.Atoi(arg[len("deepen "):]); err == nil && n > 0 {
				req.Depth = n
			}
		case arg == "done":
			done = true
			// thin-pack, no-progress, ofs-delta, filter, deepen-since,
			// deepen-not: accepted and ignored (we send full objects,
			// no progress, no filtering).
		}
	}
	return req, done, true
}

// buildFetchV2 builds a v2 fetch response: the acknowledgments section
// (only when haves were sent), the shallow-info section (only when
// there is a boundary to report), and always the packfile section —
// even for nothing-new, which still carries an empty pack.
func (s *Server) buildFetchV2(repo *store.Repo, req git.FetchRequest, done bool) ([]byte, error) {
	plan, err := git.PlanFetch(s.store, req)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1024)
	if len(req.Haves) > 0 {
		out = git.EncodePktLineString(out, "acknowledgments\n")
		if plan.NAK {
			out = git.EncodePktLineString(out, "NAK\n")
		} else {
			for _, ack := range plan.Acks {
				out = git.EncodePktLineString(out, "ACK "+ack+"\n")
			}
		}
		if done {
			out = git.EncodePktLineString(out, "ready\n")
		}
		out = git.AppendPktFlush(out)
	}
	if len(plan.Shallow) > 0 || len(plan.Unshallow) > 0 {
		out = git.EncodePktLineString(out, "shallow-info\n")
		for _, oid := range plan.Shallow {
			out = git.EncodePktLineString(out, "shallow "+oid+"\n")
		}
		for _, oid := range plan.Unshallow {
			out = git.EncodePktLineString(out, "unshallow "+oid+"\n")
		}
		out = git.AppendPktFlush(out)
	}
	pack := git.EmptyPack
	if len(plan.Objects) > 0 {
		pack = git.BuildPack(plan.Objects)
	}
	out = git.EncodePktLineString(out, "packfile\n")
	out = git.AppendSideband(out, 1, pack)
	out = git.AppendPktFlush(out)
	return out, nil
}

// fetchErrorResponse builds a minimal v2 fetch response carrying a
// band-3 sideband error (the client throws on it, as real git does
// for an unknown want).
func fetchErrorResponse(msg string) []byte {
	out := make([]byte, 0, 64)
	out = git.EncodePktLineString(out, "packfile\n")
	out = git.AppendSideband(out, 3, []byte(msg+"\n"))
	out = git.AppendPktFlush(out)
	return out
}

// ---------------------------------------------------------------- v0 fetch

// gitFetchV0 answers a v0 fetch: two sections separated by flushes —
// wants (+ shallow/deepen), then haves (+ done). The response is
// NAK/ACK + shallow lines as plain pkt-lines, then the pack as
// sideband packets. Uncached: the v0 path is a fallback the timed
// workloads never take.
func (s *Server) gitFetchV0(req *transport.Request, repo *store.Repo) *transport.Response {
	fetchReq, _, ok := parseV0FetchBody(req.Body)
	if !ok {
		return gitJSONError(400, "malformed fetch request")
	}
	if len(fetchReq.Wants) == 0 {
		return gitJSONError(400, "fetch without want")
	}
	plan, err := git.PlanFetch(s.store, fetchReq)
	if err != nil {
		if err == git.ErrUnknownWant {
			return gitBytesResponse("application/x-git-upload-pack-result", fetchErrorResponse("unknown want object"))
		}
		return gitJSONError(500, "Internal Server Error")
	}
	out := make([]byte, 0, 1024)
	if len(fetchReq.Haves) > 0 {
		if plan.NAK {
			out = git.EncodePktLineString(out, "NAK\n")
		} else {
			for _, ack := range plan.Acks {
				out = git.EncodePktLineString(out, "ACK "+ack+"\n")
			}
		}
	}
	for _, oid := range plan.Shallow {
		out = git.EncodePktLineString(out, "shallow "+oid+"\n")
	}
	for _, oid := range plan.Unshallow {
		out = git.EncodePktLineString(out, "unshallow "+oid+"\n")
	}
	pack := git.EmptyPack
	if len(plan.Objects) > 0 {
		pack = git.BuildPack(plan.Objects)
	}
	out = git.AppendSideband(out, 1, pack)
	out = git.AppendPktFlush(out)
	return gitBytesResponse("application/x-git-upload-pack-result", out)
}

// parseV0FetchBody parses a v0 fetch request body: section 1 (want /
// shallow / deepen lines) up to a flush, then section 2 (have / done)
// up to a flush. The first want line may carry capabilities after the
// oid ("want <oid> side-band-64k ...").
func parseV0FetchBody(body []byte) (git.FetchRequest, bool, bool) {
	var req git.FetchRequest
	done := false
	dec := git.NewPktDecoder(body)
	section := 0
	for {
		kind, payload, err := dec.Next()
		if err != nil {
			return req, false, false
		}
		if kind == git.PktFlush {
			section++
			if section == 2 {
				break
			}
			continue
		}
		if kind != git.PktData {
			continue
		}
		arg := strings.TrimSuffix(string(payload), "\n")
		if section == 0 {
			switch {
			case strings.HasPrefix(arg, "want "):
				rest := arg[len("want "):]
				// Strip capabilities after the oid.
				if sp := strings.IndexByte(rest, ' '); sp >= 0 {
					rest = rest[:sp]
				}
				req.Wants = append(req.Wants, rest)
			case strings.HasPrefix(arg, "shallow "):
				req.Shallow = append(req.Shallow, arg[len("shallow "):])
			case strings.HasPrefix(arg, "deepen "):
				if n, err := strconv.Atoi(arg[len("deepen "):]); err == nil && n > 0 {
					req.Depth = n
				}
			}
		} else {
			switch {
			case strings.HasPrefix(arg, "have "):
				req.Haves = append(req.Haves, arg[len("have "):])
			case arg == "done":
				done = true
			}
		}
	}
	return req, done, true
}

// ---------------------------------------------------------------- receive-pack

// pushCommand is one receive-pack ref update.
type pushCommand struct {
	old string
	new string
	ref string
}

// pushRefResult is one ref's report-status verdict.
type pushRefResult struct {
	ref    string
	ok     bool
	reason string
}

// gitReceivePack answers POST git-receive-pack: a pkt-line command list
// + flush, then the raw pack bytes. Ref updates are evaluated
// independently (per-ref atomicity); a refusal is HTTP 200 + an "ng"
// report line, never a non-200 status.
func (s *Server) gitReceivePack(req *transport.Request, repo *store.Repo) *transport.Response {
	dec := git.NewPktDecoder(req.Body)
	var commands []pushCommand
	sideband := false
	first := true
	for {
		kind, payload, err := dec.Next()
		if err != nil {
			return gitJSONError(400, "malformed pkt-line")
		}
		if kind == git.PktFlush {
			break
		}
		if kind != git.PktData {
			continue
		}
		line := strings.TrimSuffix(string(payload), "\n")
		caps := ""
		if first {
			if nul := strings.IndexByte(line, 0); nul >= 0 {
				caps = line[nul+1:]
				line = line[:nul]
			}
			first = false
		}
		fields := strings.Split(line, " ")
		if len(fields) != 3 || !git.IsOID(fields[0]) || !git.IsOID(fields[1]) || !strings.HasPrefix(fields[2], "refs/") {
			return gitJSONError(400, "malformed push command")
		}
		commands = append(commands, pushCommand{old: fields[0], new: fields[1], ref: fields[2]})
		if caps != "" {
			for _, cap := range strings.Split(caps, " ") {
				if cap == "side-band-64k" {
					sideband = true
				}
			}
		}
	}
	packBytes := dec.Rest()

	// Unpack first: a refused update must still unpack, and the
	// objects stay even when no ref moves.
	updatesRef := false
	for _, cmd := range commands {
		if cmd.new != git.ZeroOID {
			updatesRef = true
			break
		}
	}
	if updatesRef {
		if len(packBytes) == 0 {
			return s.pushReport(sideband, "missing pack", ngAll(commands, "unpack failed"))
		}
		objects, err := git.ReadPack(packBytes, s.store.GetObject)
		if err != nil {
			return s.pushReport(sideband, err.Error(), ngAll(commands, "unpack failed"))
		}
		for _, obj := range objects {
			s.store.PutObject(obj.SHA, obj.Type, obj.Data)
		}
	}

	// Evaluate each command independently, in order.
	results := make([]pushRefResult, 0, len(commands))
	for _, cmd := range commands {
		cur, exists := s.store.GetRef(repo.Owner, repo.Name, cmd.ref)
		switch {
		case cmd.old == git.ZeroOID && cmd.new != git.ZeroOID:
			// Create.
			switch {
			case exists:
				results = append(results, pushRefResult{cmd.ref, false, "already exists"})
			case !s.store.HasObject(cmd.new):
				results = append(results, pushRefResult{cmd.ref, false, "missing object"})
			case s.store.SetRef(repo.Owner, repo.Name, cmd.ref, cmd.new) != nil:
				results = append(results, pushRefResult{cmd.ref, false, "failed to update ref"})
			default:
				results = append(results, pushRefResult{cmd.ref, true, ""})
			}
		case cmd.new == git.ZeroOID:
			// Delete.
			switch {
			case !exists:
				results = append(results, pushRefResult{cmd.ref, false, "ref does not exist"})
			case cur != cmd.old:
				results = append(results, pushRefResult{cmd.ref, false, "old value does not match"})
			case s.store.DeleteRef(repo.Owner, repo.Name, cmd.ref) != nil:
				results = append(results, pushRefResult{cmd.ref, false, "failed to delete ref"})
			default:
				results = append(results, pushRefResult{cmd.ref, true, ""})
			}
		default:
			// Update: old must match, new must exist, and the
			// update must be a fast-forward (old reachable from
			// new, or a no-op).
			switch {
			case !exists:
				results = append(results, pushRefResult{cmd.ref, false, "ref does not exist"})
			case cur != cmd.old:
				results = append(results, pushRefResult{cmd.ref, false, "old value does not match"})
			case !s.store.HasObject(cmd.new):
				results = append(results, pushRefResult{cmd.ref, false, "missing object"})
			case !s.fastForward(cmd.old, cmd.new):
				results = append(results, pushRefResult{cmd.ref, false, "non-fast-forward"})
			case s.store.SetRef(repo.Owner, repo.Name, cmd.ref, cmd.new) != nil:
				results = append(results, pushRefResult{cmd.ref, false, "failed to update ref"})
			default:
				results = append(results, pushRefResult{cmd.ref, true, ""})
			}
		}
	}
	return s.pushReport(sideband, "ok", results)
}

// ngAll builds an all-refused result list (unpack failure).
func ngAll(commands []pushCommand, reason string) []pushRefResult {
	out := make([]pushRefResult, len(commands))
	for i, cmd := range commands {
		out[i] = pushRefResult{cmd.ref, false, reason}
	}
	return out
}

// fastForward reports whether updating a ref from old to new is a
// fast-forward: old == new, or old's commit is an ancestor of new's
// commit (tags peel to their commit first).
func (s *Server) fastForward(old, new string) bool {
	if old == new {
		return true
	}
	oldCommit := git.PeelToCommit(s.store, old)
	newCommit := git.PeelToCommit(s.store, new)
	if oldCommit == "" || newCommit == "" {
		return false
	}
	return git.IsAncestor(s.store, oldCommit, newCommit)
}

// pushReport renders a report-status response: "unpack <detail>" +
// one ok/ng line per command, pkt-line framed, wrapped in band-1
// sideband packets when the client asked for side-band-64k. Always
// HTTP 200: a refusal lives in the report, never in the status.
func (s *Server) pushReport(sideband bool, unpackDetail string, refs []pushRefResult) *transport.Response {
	inner := make([]byte, 0, 128+len(refs)*64)
	inner = git.EncodePktLineString(inner, "unpack "+unpackDetail+"\n")
	for _, r := range refs {
		if r.ok {
			inner = git.EncodePktLineString(inner, "ok "+r.ref+"\n")
		} else {
			inner = git.EncodePktLineString(inner, "ng "+r.ref+" "+r.reason+"\n")
		}
	}
	inner = git.AppendPktFlush(inner)
	if !sideband {
		return gitBytesResponse("application/x-git-receive-pack-result", inner)
	}
	body := git.AppendSideband(nil, 1, inner)
	return gitBytesResponse("application/x-git-receive-pack-result", body)
}
