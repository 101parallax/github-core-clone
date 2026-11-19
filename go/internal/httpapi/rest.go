// REST v3 dispatcher: the full GitHub REST API surface the conformance
// suite drives (checks-rest.ts: repos 15 + issues 15 + pulls 20 +
// protocol 5), plus the endpoints MCP setup relies on (GET /user,
// GET /branches/{branch}, GET /git/refs/heads/{branch}).
//
// Performance notes (GHC-RESEARCH.md §5):
//   - P0-5: every response type is encoded by the hand-rolled encoder in
//     json.go; encoding/json is used only to parse request bodies.
//   - P0-6: single-issue GETs serve from a pre-serialized cache keyed by
//     (repo, number); the read workload GETs the same issue 2,000x, so a
//     hit is a map lookup plus a write. Cache entries carry a snapshot of
//     the issue's mutable fields and are re-validated against the live
//     issue on every hit, so cross-surface mutations (GraphQL closeIssue)
//     can never serve stale bytes. Label mutations and repo deletion
//     invalidate the repo's entries explicitly.
//   - P1-3: issue create is a single store lock (CreateIssue) plus one
//     json.Unmarshal on the already-buffered body; label validation
//     runs one ListLabels call and is skipped entirely when the request
//     carries no labels (the write workload sends none).
//   - P0-9: response buffers are pre-sized from the payload; P0-10 does
//     not apply to response bytes (they escape into the Response and must
//     outlive the handler), so no pooled buffer is ever returned.
//   - The store lock is never held across JSON encoding or I/O: handlers
//     copy what they need under the lock (the store's List* methods
//     already return fresh slices) and encode after.
//
// Naming: every helper in this file is prefixed `rest` (except the
// contract names handleREST and the json.go encoders) so the package
// stays collision-free with W4's graphql.go/mcp.go. Two helpers are
// shared with W4: squashMerge (GraphQL/MCP merge) and restPRDiff
// (GraphQL pullRequest.files).
package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"forge/internal/git"
	"forge/internal/store"
	"forge/internal/transport"
)

// Static response bodies (immutable, shared across requests).
var (
	restRootBody = []byte(`{"current_user_url":"/api/v3/user","repository_url":"/api/v3/repos/{owner}/{repo}"}`)
	restMetaBody = []byte(`{"installed_version":"1.0.0"}`)
)

// Sentinel errors for the tree helpers.
var (
	errRestNotFound = errors.New("rest: path not found")
	errRestIsDir    = errors.New("rest: path is a directory")
	errRestNotDir   = errors.New("rest: path component is not a directory")
	errRestBadTree  = errors.New("rest: corrupt tree object")
)

// handleREST is the REST v3 dispatcher (INTERFACE.md §3). Auth is checked
// by the dispatcher in http.go before this runs; every response here is
// JSON and carries X-GitHub-Request-Id.
func (s *Server) handleREST(req *transport.Request) *transport.Response {
	resp := s.dispatchREST(req)
	if resp == nil {
		resp = jsonError(500, "Internal Server Error")
	}
	if resp.Headers == nil {
		resp.Headers = make(map[string]string, 2)
	}
	if _, ok := resp.Headers["X-GitHub-Request-Id"]; !ok {
		resp.Headers["X-GitHub-Request-Id"] = s.requestID(req)
	}
	return resp
}

// dispatchREST routes one request. The /api/v3 prefix is stripped when
// present; bare /user, /repos and / paths (which the dispatcher also
// routes here) work the same way.
func (s *Server) dispatchREST(req *transport.Request) *transport.Response {
	p := req.Path
	if p == "/api/v3" {
		p = ""
	} else if strings.HasPrefix(p, "/api/v3/") {
		p = p[len("/api/v3"):]
	}
	if len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	if p == "" || p == "/" {
		if req.Method != "GET" {
			return jsonError(404, "Not Found")
		}
		resp := jsonResponse(200, restRootBody)
		restSetHeader(resp, "X-OAuth-Scopes", "repo, read:org")
		return resp
	}
	segs := strings.Split(p[1:], "/")
	switch segs[0] {
	case "meta":
		if req.Method == "GET" && len(segs) == 1 {
			return jsonResponse(200, restMetaBody)
		}
		return jsonError(404, "Not Found")
	case "user":
		return s.dispatchUser(req, segs)
	case "repos":
		return s.dispatchRepos(req, segs)
	default:
		return jsonError(404, "Not Found")
	}
}

// dispatchUser routes /user and /user/repos.
func (s *Server) dispatchUser(req *transport.Request, segs []string) *transport.Response {
	if len(segs) == 1 {
		if req.Method != "GET" {
			return jsonError(404, "Not Found")
		}
		buf := make([]byte, 0, 160)
		buf = encodeUser(buf, s.store.Viewer())
		return jsonResponse(200, buf)
	}
	if len(segs) == 2 && segs[1] == "repos" {
		switch req.Method {
		case "GET":
			return s.restListUserRepos(req)
		case "POST":
			return s.restCreateRepo(req)
		}
	}
	return jsonError(404, "Not Found")
}

// dispatchRepos routes /repos/{owner}/{name} and everything under it.
// The repository is resolved once here; a foreign owner is a 404, never
// a 403, and a missing repository is a JSON 404 on every sub-route.
func (s *Server) dispatchRepos(req *transport.Request, segs []string) *transport.Response {
	if len(segs) < 3 {
		return jsonError(404, "Not Found")
	}
	owner, name := segs[1], segs[2]
	if owner != store.ViewerLogin {
		return jsonError(404, "Not Found")
	}
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	repoKey := repo.Key()
	if len(segs) == 3 {
		switch req.Method {
		case "GET":
			return s.restGetRepo(repo)
		case "PATCH":
			return s.restPatchRepo(req, repo)
		case "DELETE":
			return s.restDeleteRepo(repo)
		}
		return jsonError(404, "Not Found")
	}
	switch segs[3] {
	case "branches":
		return s.restBranches(req, repo, segs[4:])
	case "git":
		return s.restGitRefs(req, repo, segs[4:])
	case "commits":
		return s.restCommits(req, repo, segs[4:])
	case "contents":
		return s.restContents(req, repo, segs[4:])
	case "labels":
		return s.restLabels(req, repo, repoKey, segs[4:])
	case "issues":
		return s.restIssues(req, repo, repoKey, segs[4:])
	case "pulls":
		return s.restPulls(req, repo, repoKey, segs[4:])
	default:
		return jsonError(404, "Not Found")
	}
}

// restSetHeader sets a response header, allocating the map when needed.
func restSetHeader(resp *transport.Response, key, value string) {
	if resp.Headers == nil {
		resp.Headers = make(map[string]string, 2)
	}
	resp.Headers[key] = value
}

// restNoContent is a 204 with an empty body.
func restNoContent() *transport.Response {
	return &transport.Response{Status: 204}
}

// restAtoi parses a non-negative integer path segment.
func restAtoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// restIsHex reports whether s is all hexadecimal digits.
func restIsHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// restEqualStrings compares two string slices element-wise.
func restEqualStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// restLabelMap builds a name -> label lookup from one ListLabels call.
// It returns nil when the repository has no labels.
func (s *Server) restLabelMap(repoKey string) map[string]*store.Label {
	labels := s.store.ListLabels(repoKey)
	if len(labels) == 0 {
		return nil
	}
	m := make(map[string]*store.Label, len(labels))
	for _, l := range labels {
		m[l.Name] = l
	}
	return m
}

// restEncodeCtx builds the encoder context for one request.
func (s *Server) restEncodeCtx(labels map[string]*store.Label) *restEncodeCtx {
	return &restEncodeCtx{now: s.store.NowISO(), labels: labels}
}

// ---------------------------------------------------------------- pagination

// restPage is a parsed ?page=&per_page= pair.
type restPage struct {
	page, perPage int
}

// restParsePage parses pagination parameters: page defaults to 1,
// per_page defaults to 30 and clamps to GitHub's maximum of 100.
func restParsePage(req *transport.Request) restPage {
	page, perPage := 1, 30
	if v := req.QueryParam("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := req.QueryParam("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			perPage = n
		}
	}
	if perPage > 100 {
		perPage = 100
	}
	return restPage{page, perPage}
}

// bounds returns the [start, end) slice bounds for this page.
func (p restPage) bounds(total int) (int, int) {
	start := (p.page - 1) * p.perPage
	if start >= total {
		return total, total
	}
	end := start + p.perPage
	if end > total {
		end = total
	}
	return start, end
}

// restBaseQuery rebuilds the query string from the given keys that are
// present in the request, excluding page/per_page. It is used to keep
// filters (state, sort, direction) in Link URLs.
func restBaseQuery(req *transport.Request, keys ...string) string {
	var b []byte
	for _, k := range keys {
		v := req.QueryParam(k)
		if v == "" {
			continue
		}
		if len(b) > 0 {
			b = append(b, '&')
		}
		b = append(b, k...)
		b = append(b, '=')
		b = append(b, url.QueryEscape(v)...)
	}
	return string(b)
}

// restPageURL appends an absolute same-origin URL for the given page.
// The client refuses to follow off-origin Link URLs, so the host comes
// from the request's own Host header.
func restPageURL(dst []byte, req *transport.Request, baseQuery string, page, perPage int) []byte {
	dst = append(dst, "http://"...)
	dst = append(dst, req.Header("host")...)
	dst = append(dst, req.Path...)
	dst = append(dst, '?')
	if baseQuery != "" {
		dst = append(dst, baseQuery...)
		dst = append(dst, '&')
	}
	dst = append(dst, "page="...)
	dst = strconv.AppendInt(dst, int64(page), 10)
	dst = append(dst, "&per_page="...)
	dst = strconv.AppendInt(dst, int64(perPage), 10)
	return dst
}

// restLinkHeader builds the GitHub Link header for a paginated list, or
// "" when everything fits on one page.
func restLinkHeader(req *transport.Request, baseQuery string, total int, p restPage) string {
	last := (total + p.perPage - 1) / p.perPage
	if last < 1 {
		last = 1
	}
	if last == 1 {
		return ""
	}
	var b []byte
	add := func(page int, rel string) {
		if len(b) > 0 {
			b = append(b, ',', ' ')
		}
		b = append(b, '<')
		b = restPageURL(b, req, baseQuery, page, p.perPage)
		b = append(b, '>', ';', ' ', 'r', 'e', 'l', '=', '"')
		b = append(b, rel...)
		b = append(b, '"')
	}
	if p.page > 1 {
		add(1, "first")
		add(p.page-1, "prev")
	}
	if p.page < last {
		add(p.page+1, "next")
		add(last, "last")
	}
	return string(b)
}

// ---------------------------------------------------------------- issue cache (P0-6)

// restIssueCacheKey keys the pre-serialized single-issue cache.
type restIssueCacheKey struct {
	repo string
	num  int
}

// restCachedIssue is one pre-serialized issue response plus a snapshot of
// the issue's mutable fields. Entries are immutable once published: a
// re-encode allocates a new struct, so readers never see a torn entry.
type restCachedIssue struct {
	body   []byte
	title  string
	text   string
	state  string
	labels []string // copy of the issue's label names
	closed bool     // ClosedAt != nil
}

var restIssueCacheMu sync.RWMutex
var restIssueCache = make(map[restIssueCacheKey]*restCachedIssue)

// restCachedIssueJSON returns the cached encoded bytes for an issue when
// the live issue still matches the snapshot, or nil on a miss or a
// stale entry. The snapshot comparison is what makes the cache safe
// across surfaces: a GraphQL closeIssue changes state/closedAt, so the
// next REST GET re-encodes instead of serving stale bytes.
func restCachedIssueJSON(repoKey string, num int, issue *store.Issue) []byte {
	restIssueCacheMu.RLock()
	c, ok := restIssueCache[restIssueCacheKey{repoKey, num}]
	restIssueCacheMu.RUnlock()
	if !ok {
		return nil
	}
	if c.title != issue.Title || c.text != issue.Body || c.state != issue.State ||
		c.closed != (issue.ClosedAt != nil) || !restEqualStrings(c.labels, issue.Labels) {
		return nil
	}
	return c.body
}

// restStoreCachedIssue publishes freshly encoded issue bytes.
func restStoreCachedIssue(repoKey string, num int, issue *store.Issue, body []byte) {
	c := &restCachedIssue{
		body:   body,
		title:  issue.Title,
		text:   issue.Body,
		state:  issue.State,
		labels: append([]string(nil), issue.Labels...),
		closed: issue.ClosedAt != nil,
	}
	restIssueCacheMu.Lock()
	restIssueCache[restIssueCacheKey{repoKey, num}] = c
	restIssueCacheMu.Unlock()
}

// restInvalidateIssue drops one cached issue (after a PATCH).
func restInvalidateIssue(repoKey string, num int) {
	restIssueCacheMu.Lock()
	delete(restIssueCache, restIssueCacheKey{repoKey, num})
	restIssueCacheMu.Unlock()
}

// restInvalidateIssueRepo drops every cached issue of a repository
// (after repo deletion, or a label create/update/delete: cached issue
// bytes embed label colours and names).
func restInvalidateIssueRepo(repoKey string) {
	restIssueCacheMu.Lock()
	for k := range restIssueCache {
		if k.repo == repoKey {
			delete(restIssueCache, k)
		}
	}
	restIssueCacheMu.Unlock()
}

// ---------------------------------------------------------------- repositories

// restCreateRepo handles POST /user/repos. A duplicate name is a 422
// whose message contains "already exists".
func (s *Server) restCreateRepo(req *transport.Request) *transport.Response {
	var body struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		Private       bool   `json:"private"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	if body.Name == "" {
		return jsonError(422, "Validation Failed: name is required")
	}
	repo, err := s.store.CreateRepo(store.ViewerLogin, body.Name, store.RepoOptions{
		Description:   body.Description,
		Private:       body.Private,
		DefaultBranch: body.DefaultBranch,
	})
	if err == store.ErrRepoExists {
		return jsonError(422, "Repository already exists")
	}
	if err != nil {
		return jsonError(500, "Internal Server Error")
	}
	buf := make([]byte, 0, 256+len(repo.Name)+len(repo.Description))
	buf = encodeRepo(buf, repo, s.restEncodeCtx(nil))
	return jsonResponse(201, buf)
}

// restListUserRepos handles GET /user/repos with Link pagination.
func (s *Server) restListUserRepos(req *transport.Request) *transport.Response {
	repos := s.store.ListRepos(store.ViewerLogin)
	p := restParsePage(req)
	start, end := p.bounds(len(repos))
	page := repos[start:end]
	buf := make([]byte, 0, len(page)*220+2)
	buf = encodeRepoList(buf, page, s.restEncodeCtx(nil))
	resp := jsonResponse(200, buf)
	if link := restLinkHeader(req, "", len(repos), p); link != "" {
		restSetHeader(resp, "Link", link)
	}
	return resp
}

// restGetRepo handles GET /repos/{o}/{r}.
func (s *Server) restGetRepo(repo *store.Repo) *transport.Response {
	buf := make([]byte, 0, 256+len(repo.Name)+len(repo.Description))
	buf = encodeRepo(buf, repo, s.restEncodeCtx(nil))
	return jsonResponse(200, buf)
}

// restPatchRepo handles PATCH /repos/{o}/{r} (description, private,
// default_branch).
func (s *Server) restPatchRepo(req *transport.Request, repo *store.Repo) *transport.Response {
	var body struct {
		Description   *string `json:"description"`
		Private       *bool   `json:"private"`
		DefaultBranch *string `json:"default_branch"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	updated, err := s.store.UpdateRepo(repo.Owner, repo.Name, func(r *store.Repo) error {
		if body.Description != nil {
			r.Description = *body.Description
		}
		if body.Private != nil {
			r.Private = *body.Private
		}
		if body.DefaultBranch != nil && *body.DefaultBranch != "" {
			r.DefaultBranch = *body.DefaultBranch
		}
		return nil
	})
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 256+len(updated.Name)+len(updated.Description))
	buf = encodeRepo(buf, updated, s.restEncodeCtx(nil))
	return jsonResponse(200, buf)
}

// restDeleteRepo handles DELETE /repos/{o}/{r}: 204 with an empty body.
func (s *Server) restDeleteRepo(repo *store.Repo) *transport.Response {
	if err := s.store.DeleteRepo(repo.Owner, repo.Name); err != nil {
		return jsonError(404, "Not Found")
	}
	restInvalidateIssueRepo(repo.Key())
	return restNoContent()
}

// ---------------------------------------------------------------- branches and refs

// restBranches handles GET /branches (list) and GET /branches/{branch}
// (one branch; the name may contain '/').
func (s *Server) restBranches(req *transport.Request, repo *store.Repo, rest []string) *transport.Response {
	if req.Method != "GET" {
		return jsonError(404, "Not Found")
	}
	if len(rest) == 0 {
		branches := s.store.ListBranches(repo.Owner, repo.Name)
		buf := make([]byte, 0, len(branches)*80+2)
		buf = encodeBranchList(buf, branches)
		return jsonResponse(200, buf)
	}
	branch := strings.Join(rest, "/")
	sha, ok := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+branch)
	if !ok {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 80+len(branch))
	buf = encodeBranch(buf, branch, sha)
	return jsonResponse(200, buf)
}

// restGitRefs handles the Git Data API:
// POST /git/refs (create a ref), GET /git/refs/{ref...} and
// DELETE /git/refs/{ref...}. The ref suffix may contain '/'.
func (s *Server) restGitRefs(req *transport.Request, repo *store.Repo, rest []string) *transport.Response {
	if len(rest) == 0 || rest[0] != "refs" {
		return jsonError(404, "Not Found")
	}
	if len(rest) == 1 {
		if req.Method != "POST" {
			return jsonError(404, "Not Found")
		}
		return s.restCreateRef(req, repo)
	}
	refname := "refs/" + strings.Join(rest[1:], "/")
	switch req.Method {
	case "GET":
		sha, ok := s.store.GetRef(repo.Owner, repo.Name, refname)
		if !ok {
			return jsonError(404, "Not Found")
		}
		buf := make([]byte, 0, 80+len(refname))
		buf = encodeRef(buf, refname, sha)
		return jsonResponse(200, buf)
	case "DELETE":
		if err := s.store.DeleteRef(repo.Owner, repo.Name, refname); err != nil {
			return jsonError(404, "Not Found")
		}
		return restNoContent()
	default:
		return jsonError(404, "Not Found")
	}
}

// restCreateRef handles POST /git/refs. The sha must name an existing
// object and the ref must not exist yet; both failures are 422.
func (s *Server) restCreateRef(req *transport.Request, repo *store.Repo) *transport.Response {
	var body struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	if body.Ref == "" || !strings.HasPrefix(body.Ref, "refs/") {
		return jsonError(422, "Validation Failed: ref must start with refs/")
	}
	if body.SHA == "" || !s.store.HasObject(body.SHA) {
		return jsonError(422, "Validation Failed: sha does not name an existing object")
	}
	if _, exists := s.store.GetRef(repo.Owner, repo.Name, body.Ref); exists {
		return jsonError(422, "Reference already exists")
	}
	if err := s.store.SetRef(repo.Owner, repo.Name, body.Ref, body.SHA); err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 80+len(body.Ref))
	buf = encodeRef(buf, body.Ref, body.SHA)
	return jsonResponse(201, buf)
}

// ---------------------------------------------------------------- commits

// restCommits handles GET /commits (list, newest first, ?sha=<ref>
// filters to a branch) and GET /commits/{sha} (one commit).
func (s *Server) restCommits(req *transport.Request, repo *store.Repo, rest []string) *transport.Response {
	if req.Method != "GET" {
		return jsonError(404, "Not Found")
	}
	if len(rest) == 0 {
		return s.restListCommits(req, repo)
	}
	if len(rest) == 1 {
		commit := s.restParseCommit(rest[0])
		if commit == nil {
			return jsonError(404, "Not Found")
		}
		buf := make([]byte, 0, 96+len(commit.Message))
		buf = encodeCommit(buf, rest[0], commit.Message)
		return jsonResponse(200, buf)
	}
	return jsonError(404, "Not Found")
}

// restListCommits lists a branch's history newest first. With no ?sha=
// the default branch is used; an unborn repository lists no commits.
func (s *Server) restListCommits(req *transport.Request, repo *store.Repo) *transport.Response {
	ref := req.QueryParam("sha")
	tip, ok := s.restResolveCommit(repo, ref)
	if !ok {
		if ref == "" {
			return jsonResponse(200, []byte("[]"))
		}
		return jsonError(404, "Not Found")
	}
	shas, messages := s.restCommitHistory(tip)
	buf := make([]byte, 0, len(shas)*120+2)
	buf = encodeCommitList(buf, shas, messages)
	return jsonResponse(200, buf)
}

// restCommitHistory walks a commit's ancestry newest first (depth-first,
// first parent first on linear history), returning parallel sha/message
// slices.
func (s *Server) restCommitHistory(tip string) (shas, messages []string) {
	seen := make(map[string]bool)
	stack := []string{tip}
	for len(stack) > 0 {
		sha := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[sha] {
			continue
		}
		seen[sha] = true
		commit := s.restParseCommit(sha)
		if commit == nil {
			continue
		}
		shas = append(shas, sha)
		messages = append(messages, commit.Message)
		stack = append(stack, commit.Parents...)
	}
	return shas, messages
}

// ---------------------------------------------------------------- contents API

// restContents routes GET/PUT/DELETE /contents/{path}. The path may be
// empty (the root listing for GET) and may contain '/'.
func (s *Server) restContents(req *transport.Request, repo *store.Repo, rest []string) *transport.Response {
	path := strings.Join(rest, "/")
	switch req.Method {
	case "GET":
		return s.restContentsGet(req, repo, path)
	case "PUT":
		return s.restContentsPut(req, repo, path)
	case "DELETE":
		return s.restContentsDelete(req, repo, path)
	default:
		return jsonError(404, "Not Found")
	}
}

// restContentsGet serves a file (base64 content + blob sha) or a
// directory listing at ?ref= (default: the default branch).
func (s *Server) restContentsGet(req *transport.Request, repo *store.Repo, path string) *transport.Response {
	tip, ok := s.restResolveCommit(repo, req.QueryParam("ref"))
	if !ok {
		return jsonError(404, "Not Found")
	}
	commit := s.restParseCommit(tip)
	if commit == nil {
		return jsonError(404, "Not Found")
	}
	if path == "" {
		return s.restDirListing(commit.Tree, "")
	}
	kind, sha := s.restLookupPath(commit.Tree, path)
	switch kind {
	case "file":
		data, typ, ok := s.store.GetObject(sha)
		if !ok || typ != git.ObjBlob {
			return jsonError(404, "Not Found")
		}
		name := path
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			name = path[i+1:]
		}
		buf := make([]byte, 0, 160+len(path)+len(data)*2)
		buf = encodeContentFile(buf, name, path, sha, base64.StdEncoding.EncodeToString(data), int64(len(data)))
		return jsonResponse(200, buf)
	case "dir":
		return s.restDirListing(sha, path)
	default:
		return jsonError(404, "Not Found")
	}
}

// restDirListing serves a directory's immediate entries.
func (s *Server) restDirListing(treeSHA, dirPath string) *transport.Response {
	data, typ, ok := s.store.GetObject(treeSHA)
	if !ok || typ != git.ObjTree {
		return jsonError(404, "Not Found")
	}
	entries, err := git.ParseTree(data)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, len(entries)*128+2)
	buf = append(buf, '[')
	for i, e := range entries {
		if i > 0 {
			buf = append(buf, ',')
		}
		typ := "file"
		if e.Mode == "40000" || e.Mode == "040000" {
			typ = "dir"
		}
		p := e.Name
		if dirPath != "" {
			p = dirPath + "/" + e.Name
		}
		buf = encodeContentEntry(buf, typ, e.Name, p, e.SHA)
	}
	buf = append(buf, ']')
	return jsonResponse(200, buf)
}

// restContentsPut creates or updates a file with a REAL git commit:
// blob + rebuilt tree chain + commit object, advancing the branch ref.
// An unborn repository accepts the first PUT (root commit). A PUT naming
// a branch that does not exist creates it from the default branch tip.
// Updating an existing file requires its current blob sha; a stale sha
// is a 409.
func (s *Server) restContentsPut(req *transport.Request, repo *store.Repo, path string) *transport.Response {
	segments := restSplitPath(path)
	if len(segments) == 0 {
		return jsonError(422, "Validation Failed: path is required")
	}
	var body struct {
		Message string `json:"message"`
		Content string `json:"content"`
		Branch  string `json:"branch"`
		SHA     string `json:"sha"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	content, err := base64.StdEncoding.DecodeString(body.Content)
	if err != nil {
		return jsonError(400, "Invalid base64 content")
	}
	branch := body.Branch
	if branch == "" {
		branch = repo.DefaultBranch
	}
	// Resolve the branch tip and the file's current state.
	var parents []string
	var parentTree string
	exists := false
	var currentBlob string
	tip, branchExists := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+branch)
	if branchExists {
		commit := s.restParseCommit(tip)
		if commit == nil {
			return jsonError(500, "Internal Server Error")
		}
		parents = []string{tip}
		parentTree = commit.Tree
	} else if branch != repo.DefaultBranch {
		// Create the branch from the default branch tip.
		defTip, ok := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+repo.DefaultBranch)
		if ok {
			commit := s.restParseCommit(defTip)
			if commit == nil {
				return jsonError(500, "Internal Server Error")
			}
			parents = []string{defTip}
			parentTree = commit.Tree
		}
	}
	if parentTree != "" {
		kind, sha := s.restLookupPath(parentTree, path)
		switch kind {
		case "file":
			exists = true
			currentBlob = sha
		case "dir":
			return jsonError(422, "Validation Failed: path is a directory")
		}
	}
	if exists {
		if body.SHA == "" {
			return jsonError(422, "Validation Failed: sha is required to update a file")
		}
		if body.SHA != currentBlob {
			return jsonError(409, "Conflict: sha does not match the current file")
		}
	}
	// Build the blob, the rebuilt tree chain, and the commit.
	blobSHA := git.HashObject(git.ObjBlob, content)
	s.store.PutObject(blobSHA, git.ObjBlob, content)
	newTree, _, err := s.restUpdateTree(parentTree, segments, blobSHA, false)
	if err != nil {
		return jsonError(422, "Validation Failed: "+err.Error())
	}
	ident := s.restCommitterIdent()
	commitBytes := git.BuildCommit(newTree, parents, ident, ident, body.Message)
	commitSHA := git.HashObject(git.ObjCommit, commitBytes)
	s.store.PutObject(commitSHA, git.ObjCommit, commitBytes)
	if err := s.store.SetRef(repo.Owner, repo.Name, "refs/heads/"+branch, commitSHA); err != nil {
		return jsonError(404, "Not Found")
	}
	status := 201
	if exists {
		status = 200
	}
	name := segments[len(segments)-1]
	buf := make([]byte, 0, 256+len(path))
	buf = append(buf, `{"content":`...)
	buf = encodeContentFile(buf, name, path, blobSHA, body.Content, int64(len(content)))
	buf = append(buf, `,"commit":{"sha":`...)
	buf = appendJSONString(buf, commitSHA)
	buf = append(buf, `,"message":`...)
	buf = appendJSONString(buf, body.Message)
	buf = append(buf, `}}`...)
	return jsonResponse(status, buf)
}

// restContentsDelete deletes a file with a REAL git commit and advances
// the branch ref. The current blob sha is required; a stale sha is a 409.
func (s *Server) restContentsDelete(req *transport.Request, repo *store.Repo, path string) *transport.Response {
	segments := restSplitPath(path)
	if len(segments) == 0 {
		return jsonError(404, "Not Found")
	}
	var body struct {
		Message string `json:"message"`
		Branch  string `json:"branch"`
		SHA     string `json:"sha"`
	}
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonError(400, "Invalid JSON body")
		}
	}
	branch := body.Branch
	if branch == "" {
		branch = repo.DefaultBranch
	}
	tip, ok := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+branch)
	if !ok {
		return jsonError(404, "Not Found")
	}
	commit := s.restParseCommit(tip)
	if commit == nil {
		return jsonError(500, "Internal Server Error")
	}
	kind, currentBlob := s.restLookupPath(commit.Tree, path)
	if kind != "file" {
		return jsonError(404, "Not Found")
	}
	if body.SHA == "" {
		return jsonError(422, "Validation Failed: sha is required to delete a file")
	}
	if body.SHA != currentBlob {
		return jsonError(409, "Conflict: sha does not match the current file")
	}
	newTree, _, err := s.restUpdateTree(commit.Tree, segments, "", true)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	ident := s.restCommitterIdent()
	commitBytes := git.BuildCommit(newTree, []string{tip}, ident, ident, body.Message)
	commitSHA := git.HashObject(git.ObjCommit, commitBytes)
	s.store.PutObject(commitSHA, git.ObjCommit, commitBytes)
	if err := s.store.SetRef(repo.Owner, repo.Name, "refs/heads/"+branch, commitSHA); err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 128)
	buf = append(buf, `{"commit":{"sha":`...)
	buf = appendJSONString(buf, commitSHA)
	buf = append(buf, `,"message":`...)
	buf = appendJSONString(buf, body.Message)
	buf = append(buf, `}}`...)
	return jsonResponse(200, buf)
}

// restSplitPath splits a repository-relative path into segments, or
// returns nil for an empty path or one containing an empty, "." or ".."
// segment (never a valid file path).
func restSplitPath(path string) []string {
	if path == "" {
		return nil
	}
	segments := strings.Split(path, "/")
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return nil
		}
	}
	return segments
}

// ---------------------------------------------------------------- git traversal helpers

// restParseCommit parses a stored commit object, or returns nil when the
// sha is unknown or not a commit.
func (s *Server) restParseCommit(sha string) *git.Commit {
	data, typ, ok := s.store.GetObject(sha)
	if !ok || typ != git.ObjCommit {
		return nil
	}
	commit, err := git.ParseCommit(data)
	if err != nil {
		return nil
	}
	return commit
}

// restResolveCommit resolves a ref query value to a commit sha: "" means
// the default branch, a 40-hex value names a commit directly, anything
// else is a branch name.
func (s *Server) restResolveCommit(repo *store.Repo, ref string) (string, bool) {
	if ref == "" {
		sha, ok := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+repo.DefaultBranch)
		return sha, ok
	}
	if len(ref) == 40 && restIsHex(ref) {
		_, typ, ok := s.store.GetObject(ref)
		if !ok || typ != git.ObjCommit {
			return "", false
		}
		return ref, true
	}
	sha, ok := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+ref)
	return sha, ok
}

// restLookupPath walks the tree at treeSHA to path. It returns the kind
// ("file" or "dir") and the blob/tree sha, or ("", "") when missing.
func (s *Server) restLookupPath(treeSHA, path string) (string, string) {
	segments := strings.Split(path, "/")
	current := treeSHA
	for i, seg := range segments {
		data, typ, ok := s.store.GetObject(current)
		if !ok || typ != git.ObjTree {
			return "", ""
		}
		entries, err := git.ParseTree(data)
		if err != nil {
			return "", ""
		}
		found := false
		for _, e := range entries {
			if e.Name != seg {
				continue
			}
			found = true
			if i == len(segments)-1 {
				if e.Mode == "40000" || e.Mode == "040000" {
					return "dir", e.SHA
				}
				return "file", e.SHA
			}
			if e.Mode != "40000" && e.Mode != "040000" {
				return "", ""
			}
			current = e.SHA
			break
		}
		if !found {
			return "", ""
		}
	}
	return "", ""
}

// restUpdateTree returns the sha of the tree at treeSHA with the file at
// segments updated: blobSHA != "" sets or replaces the file; isDelete
// removes it. treeSHA == "" means the empty tree (unborn repository).
// Intermediate trees are created as needed and empty trees are pruned on
// delete; every rebuilt tree is git-sorted, hashed and stored. The second
// return value reports whether the resulting tree is empty.
func (s *Server) restUpdateTree(treeSHA string, segments []string, blobSHA string, isDelete bool) (string, bool, error) {
	var entries []git.TreeEntry
	if treeSHA != "" {
		data, typ, ok := s.store.GetObject(treeSHA)
		if !ok || typ != git.ObjTree {
			return "", false, errRestBadTree
		}
		parsed, err := git.ParseTree(data)
		if err != nil {
			return "", false, errRestBadTree
		}
		entries = parsed
	}
	name := segments[0]
	idx := -1
	for i, e := range entries {
		if e.Name == name {
			idx = i
			break
		}
	}
	if len(segments) == 1 {
		if isDelete {
			if idx < 0 {
				return "", false, errRestNotFound
			}
			entries = append(entries[:idx], entries[idx+1:]...)
		} else {
			mode := "100644"
			if idx >= 0 {
				if entries[idx].Mode == "40000" || entries[idx].Mode == "040000" {
					return "", false, errRestIsDir
				}
				mode = entries[idx].Mode // preserve e.g. 100755
				entries[idx].SHA = blobSHA
			} else {
				entries = append(entries, git.TreeEntry{Mode: mode, Name: name, SHA: blobSHA})
			}
		}
	} else {
		var subSHA string
		if idx >= 0 {
			if entries[idx].Mode != "40000" && entries[idx].Mode != "040000" {
				return "", false, errRestNotDir
			}
			subSHA = entries[idx].SHA
		}
		newSub, subEmpty, err := s.restUpdateTree(subSHA, segments[1:], blobSHA, isDelete)
		if err != nil {
			return "", false, err
		}
		if isDelete && subEmpty {
			if idx >= 0 {
				entries = append(entries[:idx], entries[idx+1:]...)
			}
		} else if idx >= 0 {
			entries[idx].SHA = newSub
		} else {
			entries = append(entries, git.TreeEntry{Mode: "40000", Name: name, SHA: newSub})
		}
	}
	git.SortTreeEntries(entries)
	data := git.BuildTree(entries)
	sha := git.HashObject(git.ObjTree, data)
	s.store.PutObject(sha, git.ObjTree, data)
	return sha, len(entries) == 0, nil
}

// restCommitterIdent builds the deterministic author/committer line for
// forge-created commits: the viewer's name and email at the store's
// fixed timestamp, UTC.
func (s *Server) restCommitterIdent() string {
	u := s.store.Viewer()
	return u.Name + " <" + u.Email + "> " + strconv.FormatInt(s.store.Now().Unix(), 10) + " +0000"
}

// ---------------------------------------------------------------- labels

// restLabels routes GET/POST /labels and GET/PATCH/DELETE /labels/{name}.
func (s *Server) restLabels(req *transport.Request, repo *store.Repo, repoKey string, rest []string) *transport.Response {
	if len(rest) == 0 {
		switch req.Method {
		case "GET":
			labels := s.store.ListLabels(repoKey)
			buf := make([]byte, 0, len(labels)*96+2)
			buf = encodeLabelList(buf, labels)
			return jsonResponse(200, buf)
		case "POST":
			return s.restCreateLabel(req, repo, repoKey)
		}
		return jsonError(404, "Not Found")
	}
	if len(rest) != 1 {
		return jsonError(404, "Not Found")
	}
	name := rest[0]
	switch req.Method {
	case "GET":
		label, ok := s.store.GetLabel(repoKey, name)
		if !ok {
			return jsonError(404, "Not Found")
		}
		buf := make([]byte, 0, 128)
		buf = encodeLabel(buf, label)
		return jsonResponse(200, buf)
	case "PATCH":
		return s.restPatchLabel(req, repo, repoKey, name)
	case "DELETE":
		if err := s.store.DeleteLabel(repoKey, name); err != nil {
			return jsonError(404, "Not Found")
		}
		restInvalidateIssueRepo(repoKey)
		return restNoContent()
	default:
		return jsonError(404, "Not Found")
	}
}

// restCreateLabel handles POST /labels. The colour defaults to "ffffff"
// when absent (the suite sends only a name).
func (s *Server) restCreateLabel(req *transport.Request, repo *store.Repo, repoKey string) *transport.Response {
	var body struct {
		Name        string `json:"name"`
		Color       string `json:"color"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	if body.Name == "" {
		return jsonError(422, "Validation Failed: name is required")
	}
	color := body.Color
	if color == "" {
		color = "ffffff"
	}
	label, err := s.store.CreateLabel(repoKey, body.Name, color, body.Description)
	if err == store.ErrLabelExists {
		return jsonError(422, "Label already exists")
	}
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 128)
	buf = encodeLabel(buf, label)
	return jsonResponse(201, buf)
}

// restPatchLabel handles PATCH /labels/{name} (rename, recolour,
// re-describe). A rename onto an existing name is a 422.
func (s *Server) restPatchLabel(req *transport.Request, repo *store.Repo, repoKey, name string) *transport.Response {
	var body struct {
		Name        *string `json:"name"`
		Color       *string `json:"color"`
		Description *string `json:"description"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	current, ok := s.store.GetLabel(repoKey, name)
	if !ok {
		return jsonError(404, "Not Found")
	}
	newName, color, description := "", "", current.Description
	if body.Name != nil {
		newName = *body.Name
	}
	if body.Color != nil {
		color = *body.Color
	}
	if body.Description != nil {
		description = *body.Description
	}
	label, err := s.store.UpdateLabel(repoKey, name, newName, color, description)
	if err == store.ErrLabelNotFound {
		return jsonError(404, "Not Found")
	}
	if err == store.ErrLabelExists {
		return jsonError(422, "Label already exists")
	}
	if err != nil {
		return jsonError(500, "Internal Server Error")
	}
	restInvalidateIssueRepo(repoKey)
	buf := make([]byte, 0, 128)
	buf = encodeLabel(buf, label)
	return jsonResponse(200, buf)
}

// ---------------------------------------------------------------- issues

// restIssues routes /issues, /issues/{n}, /issues/{n}/comments and
// /issues/comments/{id}.
func (s *Server) restIssues(req *transport.Request, repo *store.Repo, repoKey string, rest []string) *transport.Response {
	if len(rest) == 0 {
		switch req.Method {
		case "GET":
			return s.restListIssues(req, repo, repoKey)
		case "POST":
			return s.restCreateIssue(req, repo, repoKey)
		}
		return jsonError(404, "Not Found")
	}
	// /issues/comments/{id}: PATCH/DELETE one comment without its issue.
	if rest[0] == "comments" {
		if len(rest) != 2 {
			return jsonError(404, "Not Found")
		}
		id, ok := restAtoi(rest[1])
		if !ok {
			return jsonError(404, "Not Found")
		}
		switch req.Method {
		case "PATCH":
			return s.restPatchIssueComment(req, repo, repoKey, int64(id))
		case "DELETE":
			return s.restDeleteIssueComment(repo, repoKey, int64(id))
		}
		return jsonError(404, "Not Found")
	}
	num, ok := restAtoi(rest[0])
	if !ok {
		return jsonError(404, "Not Found")
	}
	if len(rest) == 1 {
		switch req.Method {
		case "GET":
			return s.restGetIssue(req, repo, repoKey, num)
		case "PATCH":
			return s.restPatchIssue(req, repo, repoKey, num)
		}
		return jsonError(404, "Not Found")
	}
	if len(rest) == 2 && rest[1] == "comments" {
		switch req.Method {
		case "GET":
			return s.restListIssueComments(req, repo, repoKey, num)
		case "POST":
			return s.restCreateIssueComment(req, repo, repoKey, num)
		}
	}
	return jsonError(404, "Not Found")
}

// restCreateIssue handles POST /issues (P1-3: one json.Unmarshal on the
// buffered body, one ListLabels call for validation — skipped when the
// request carries no labels — and one store lock in CreateIssue).
// An unknown label is a 422.
func (s *Server) restCreateIssue(req *transport.Request, repo *store.Repo, repoKey string) *transport.Response {
	var body struct {
		Title  string   `json:"title"`
		Body   string   `json:"body"`
		Labels []string `json:"labels"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	var labelMap map[string]*store.Label
	if len(body.Labels) > 0 {
		labelMap = s.restLabelMap(repoKey)
		for _, name := range body.Labels {
			if _, ok := labelMap[name]; !ok {
				return jsonError(422, "Validation Failed: unknown label "+name)
			}
		}
	}
	issue, err := s.store.CreateIssue(repoKey, body.Title, body.Body, body.Labels)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 320+len(issue.Title)+len(issue.Body)+len(issue.Labels)*80)
	buf = encodeIssue(buf, issue, s.restEncodeCtx(labelMap))
	return jsonResponse(201, buf)
}

// restGetIssue handles GET /issues/{n} via the pre-serialized cache
// (P0-6): a hit is a map lookup plus a write.
func (s *Server) restGetIssue(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	issue, ok := s.store.GetIssue(repoKey, num)
	if !ok {
		return jsonError(404, "Not Found")
	}
	if body := restCachedIssueJSON(repoKey, num, issue); body != nil {
		return jsonResponse(200, body)
	}
	labelMap := s.restLabelMap(repoKey)
	buf := make([]byte, 0, 320+len(issue.Title)+len(issue.Body)+len(issue.Labels)*80)
	buf = encodeIssue(buf, issue, s.restEncodeCtx(labelMap))
	restStoreCachedIssue(repoKey, num, issue, buf)
	return jsonResponse(200, buf)
}

// restListIssues handles GET /issues with ?state= (open|closed|all,
// default open) and ?sort=created&direction= (asc|desc). Sorting is by
// the store's monotonic sequence number — ListIssues already returns
// creation order — never by created_at, whose values all tie.
func (s *Server) restListIssues(req *transport.Request, repo *store.Repo, repoKey string) *transport.Response {
	issues := s.store.ListIssues(repoKey)
	state := req.QueryParam("state")
	if state == "" {
		state = "open"
	}
	if state != "all" {
		filtered := issues[:0]
		for _, issue := range issues {
			if issue.State == state {
				filtered = append(filtered, issue)
			}
		}
		issues = filtered
	}
	if req.QueryParam("sort") == "created" && req.QueryParam("direction") == "desc" {
		for i, j := 0, len(issues)-1; i < j; i, j = i+1, j-1 {
			issues[i], issues[j] = issues[j], issues[i]
		}
	}
	p := restParsePage(req)
	start, end := p.bounds(len(issues))
	page := issues[start:end]
	labelMap := s.restLabelMap(repoKey)
	ctx := s.restEncodeCtx(labelMap)
	buf := make([]byte, 0, len(page)*320+2)
	buf = encodeIssueList(buf, page, ctx)
	resp := jsonResponse(200, buf)
	if link := restLinkHeader(req, restBaseQuery(req, "state", "sort", "direction"), len(issues), p); link != "" {
		restSetHeader(resp, "Link", link)
	}
	return resp
}

// restPatchIssue handles PATCH /issues/{n} (title, body, state, labels).
// Closing sets ClosedAt; reopening clears it.
func (s *Server) restPatchIssue(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	var body struct {
		State  *string   `json:"state"`
		Title  *string   `json:"title"`
		Body   *string   `json:"body"`
		Labels *[]string `json:"labels"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	if body.State != nil && *body.State != "open" && *body.State != "closed" {
		return jsonError(422, "Validation Failed: state must be open or closed")
	}
	var labelMap map[string]*store.Label
	if body.Labels != nil && len(*body.Labels) > 0 {
		labelMap = s.restLabelMap(repoKey)
		for _, name := range *body.Labels {
			if _, ok := labelMap[name]; !ok {
				return jsonError(422, "Validation Failed: unknown label "+name)
			}
		}
	}
	issue, err := s.store.UpdateIssue(repoKey, num, func(is *store.Issue) error {
		if body.Title != nil {
			is.Title = *body.Title
		}
		if body.Body != nil {
			is.Body = *body.Body
		}
		if body.Labels != nil {
			is.Labels = append([]string(nil), *body.Labels...)
		}
		if body.State != nil {
			switch *body.State {
			case "closed":
				if is.State != "closed" {
					now := s.store.Now()
					is.ClosedAt = &now
				}
				is.State = "closed"
			case "open":
				is.State = "open"
				is.ClosedAt = nil
			}
		}
		return nil
	})
	if err != nil {
		return jsonError(404, "Not Found")
	}
	restInvalidateIssue(repoKey, num)
	if labelMap == nil {
		labelMap = s.restLabelMap(repoKey)
	}
	buf := make([]byte, 0, 320+len(issue.Title)+len(issue.Body)+len(issue.Labels)*80)
	buf = encodeIssue(buf, issue, s.restEncodeCtx(labelMap))
	return jsonResponse(200, buf)
}

// restCreateIssueComment handles POST /issues/{n}/comments.
func (s *Server) restCreateIssueComment(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	var body struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	comment, err := s.store.AddIssueComment(repoKey, num, body.Body, store.ViewerLogin)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 200+len(comment.Body))
	buf = encodeComment(buf, comment, s.restEncodeCtx(nil))
	return jsonResponse(201, buf)
}

// restListIssueComments handles GET /issues/{n}/comments.
func (s *Server) restListIssueComments(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	comments, err := s.store.ListIssueComments(repoKey, num)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, len(comments)*200+2)
	buf = encodeCommentList(buf, comments, s.restEncodeCtx(nil))
	return jsonResponse(200, buf)
}

// restFindIssueComment locates the issue owning a comment id (the
// /issues/comments/{id} route carries no issue number).
func (s *Server) restFindIssueComment(repoKey string, commentID int64) (int, bool) {
	for _, issue := range s.store.ListIssues(repoKey) {
		for _, c := range issue.Comments {
			if c.ID == commentID {
				return issue.Number, true
			}
		}
	}
	return 0, false
}

// restPatchIssueComment handles PATCH /issues/comments/{id}.
func (s *Server) restPatchIssueComment(req *transport.Request, repo *store.Repo, repoKey string, commentID int64) *transport.Response {
	var body struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	num, ok := s.restFindIssueComment(repoKey, commentID)
	if !ok {
		return jsonError(404, "Not Found")
	}
	comment, err := s.store.UpdateIssueComment(repoKey, num, commentID, body.Body)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 200+len(comment.Body))
	buf = encodeComment(buf, comment, s.restEncodeCtx(nil))
	return jsonResponse(200, buf)
}

// restDeleteIssueComment handles DELETE /issues/comments/{id}: 204.
func (s *Server) restDeleteIssueComment(repo *store.Repo, repoKey string, commentID int64) *transport.Response {
	num, ok := s.restFindIssueComment(repoKey, commentID)
	if !ok {
		return jsonError(404, "Not Found")
	}
	if err := s.store.DeleteIssueComment(repoKey, num, commentID); err != nil {
		return jsonError(404, "Not Found")
	}
	return restNoContent()
}

// ---------------------------------------------------------------- pull requests

// restPulls routes /pulls, /pulls/{n}, /pulls/{n}/files,
// /pulls/{n}/merge, /pulls/{n}/reviews and /pulls/{n}/comments.
func (s *Server) restPulls(req *transport.Request, repo *store.Repo, repoKey string, rest []string) *transport.Response {
	if len(rest) == 0 {
		switch req.Method {
		case "GET":
			return s.restListPRs(req, repo, repoKey)
		case "POST":
			return s.restCreatePR(req, repo, repoKey)
		}
		return jsonError(404, "Not Found")
	}
	num, ok := restAtoi(rest[0])
	if !ok {
		return jsonError(404, "Not Found")
	}
	if len(rest) == 1 {
		if req.Method != "GET" {
			return jsonError(404, "Not Found")
		}
		pr, ok := s.store.GetPR(repoKey, num)
		if !ok {
			return jsonError(404, "Not Found")
		}
		buf := make([]byte, 0, 400+len(pr.Title)+len(pr.Body))
		buf = encodePR(buf, pr, s.restEncodeCtx(s.restLabelMap(repoKey)))
		return jsonResponse(200, buf)
	}
	if len(rest) != 2 {
		return jsonError(404, "Not Found")
	}
	switch rest[1] {
	case "files":
		if req.Method != "GET" {
			return jsonError(404, "Not Found")
		}
		return s.restPRFiles(req, repo, repoKey, num)
	case "merge":
		if req.Method != "PUT" {
			return jsonError(404, "Not Found")
		}
		return s.restMergePR(req, repo, repoKey, num)
	case "reviews":
		switch req.Method {
		case "GET":
			return s.restListReviews(req, repo, repoKey, num)
		case "POST":
			return s.restCreateReview(req, repo, repoKey, num)
		}
	case "comments":
		switch req.Method {
		case "GET":
			return s.restListPRComments(req, repo, repoKey, num)
		case "POST":
			return s.restCreatePRComment(req, repo, repoKey, num)
		}
	}
	return jsonError(404, "Not Found")
}

// restCreatePR handles POST /pulls. HeadSHA and BaseSHA are frozen from
// the head/base branch tips at creation time — GraphQL pullRequest.files
// diffs from these stored shas, so they must never be empty. An unknown
// head or base branch is a 422.
func (s *Server) restCreatePR(req *transport.Request, repo *store.Repo, repoKey string) *transport.Response {
	var body struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		Head  string `json:"head"`
		Base  string `json:"base"`
		Draft bool   `json:"draft"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	head := strings.TrimPrefix(body.Head, "refs/heads/")
	base := strings.TrimPrefix(body.Base, "refs/heads/")
	if base == "" {
		base = repo.DefaultBranch
	}
	headSHA, ok := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+head)
	if !ok {
		return jsonError(422, "Validation Failed: head branch not found")
	}
	baseSHA, ok := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+base)
	if !ok {
		return jsonError(422, "Validation Failed: base branch not found")
	}
	pr, err := s.store.CreatePR(repoKey, store.PROptions{
		Title:   body.Title,
		Body:    body.Body,
		HeadRef: head,
		HeadSHA: headSHA,
		BaseRef: base,
		BaseSHA: baseSHA,
		Draft:   body.Draft,
	})
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 400+len(pr.Title)+len(pr.Body))
	buf = encodePR(buf, pr, s.restEncodeCtx(nil))
	return jsonResponse(201, buf)
}

// restListPRs handles GET /pulls with ?state= (open|closed|all, default
// open), in creation (sequence) order.
func (s *Server) restListPRs(req *transport.Request, repo *store.Repo, repoKey string) *transport.Response {
	prs := s.store.ListPRs(repoKey)
	state := req.QueryParam("state")
	if state == "" {
		state = "open"
	}
	if state != "all" {
		filtered := prs[:0]
		for _, pr := range prs {
			if pr.State == state {
				filtered = append(filtered, pr)
			}
		}
		prs = filtered
	}
	p := restParsePage(req)
	start, end := p.bounds(len(prs))
	page := prs[start:end]
	ctx := s.restEncodeCtx(s.restLabelMap(repoKey))
	buf := make([]byte, 0, len(page)*400+2)
	buf = encodePRList(buf, page, ctx)
	resp := jsonResponse(200, buf)
	if link := restLinkHeader(req, restBaseQuery(req, "state"), len(prs), p); link != "" {
		restSetHeader(resp, "Link", link)
	}
	return resp
}

// restPRFiles handles GET /pulls/{n}/files: the merge-base diff between
// the base tip and the head tip.
func (s *Server) restPRFiles(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	pr, ok := s.store.GetPR(repoKey, num)
	if !ok {
		return jsonError(404, "Not Found")
	}
	files, err := s.restPRDiff(repo, pr)
	if err != nil {
		return jsonError(500, "Internal Server Error")
	}
	buf := make([]byte, 0, len(files)*120+2)
	buf = append(buf, '[')
	for i, f := range files {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = encodePRFile(buf, f.filename, f.status, f.additions, f.deletions)
	}
	buf = append(buf, ']')
	return jsonResponse(200, buf)
}

// restMergePR handles PUT /pulls/{n}/merge (squash-only). Unknown PR is
// a 404; a conflicted or already-merged PR is a 405.
func (s *Server) restMergePR(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	pr, ok := s.store.GetPR(repoKey, num)
	if !ok {
		return jsonError(404, "Not Found")
	}
	if len(req.Body) > 0 {
		var body struct {
			MergeMethod string `json:"merge_method"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonError(400, "Invalid JSON body")
		}
		// Only squash is ever sent; the merge is squash regardless.
	}
	sha, err := s.squashMerge(repo, pr)
	if err != nil {
		var merr *restMergeError
		if errors.As(err, &merr) {
			return jsonError(merr.status, merr.msg)
		}
		return jsonError(500, "Internal Server Error")
	}
	buf := make([]byte, 0, 128)
	buf = append(buf, `{"merged":true,"sha":`...)
	buf = appendJSONString(buf, sha)
	buf = append(buf, `,"message":"Pull Request successfully merged"}`...)
	return jsonResponse(200, buf)
}

// restCreateReview handles POST /pulls/{n}/reviews. The event field
// (APPROVE, REQUEST_CHANGES, COMMENT) maps to the review state.
func (s *Server) restCreateReview(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	var body struct {
		Body  string `json:"body"`
		Event string `json:"event"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	state := body.State
	if state == "" {
		switch body.Event {
		case "APPROVE", "APPROVED":
			state = "APPROVED"
		case "REQUEST_CHANGES", "CHANGES_REQUESTED":
			state = "CHANGES_REQUESTED"
		case "DISMISS", "DISMISSED":
			state = "DISMISSED"
		default:
			state = "COMMENTED"
		}
	}
	review, err := s.store.AddReview(repoKey, num, body.Body, state, store.ViewerLogin)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 200+len(review.Body))
	buf = encodeReview(buf, review, s.restEncodeCtx(nil))
	return jsonResponse(201, buf)
}

// restListReviews handles GET /pulls/{n}/reviews.
func (s *Server) restListReviews(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	reviews, err := s.store.ListReviews(repoKey, num)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, len(reviews)*200+2)
	buf = encodeReviewList(buf, reviews, s.restEncodeCtx(nil))
	return jsonResponse(200, buf)
}

// restCreatePRComment handles POST /pulls/{n}/comments.
func (s *Server) restCreatePRComment(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	var body struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return jsonError(400, "Invalid JSON body")
	}
	comment, err := s.store.AddPRComment(repoKey, num, body.Body, store.ViewerLogin)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, 200+len(comment.Body))
	buf = encodeComment(buf, comment, s.restEncodeCtx(nil))
	return jsonResponse(201, buf)
}

// restListPRComments handles GET /pulls/{n}/comments.
func (s *Server) restListPRComments(req *transport.Request, repo *store.Repo, repoKey string, num int) *transport.Response {
	comments, err := s.store.ListPRComments(repoKey, num)
	if err != nil {
		return jsonError(404, "Not Found")
	}
	buf := make([]byte, 0, len(comments)*200+2)
	buf = encodeCommentList(buf, comments, s.restEncodeCtx(nil))
	return jsonResponse(200, buf)
}

// ---------------------------------------------------------------- merge and diff

// restMergeError is a domain error from squashMerge carrying the HTTP
// status the endpoint must answer with (405 conflict/already-merged).
type restMergeError struct {
	status int
	msg    string
}

func (e *restMergeError) Error() string { return e.msg }

// restFlatFile is one flattened tree entry: the blob sha and its mode.
type restFlatFile struct {
	sha  string
	mode string
}

// restFlattenTree flattens the tree at treeSHA into out (path -> file).
// Gitlinks are skipped: they name commits the repo does not hold.
func (s *Server) restFlattenTree(treeSHA, prefix string, out map[string]restFlatFile) {
	if treeSHA == "" {
		return
	}
	data, typ, ok := s.store.GetObject(treeSHA)
	if !ok || typ != git.ObjTree {
		return
	}
	entries, err := git.ParseTree(data)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := prefix + e.Name
		switch {
		case e.Mode == "40000" || e.Mode == "040000":
			s.restFlattenTree(e.SHA, p+"/", out)
		case e.Mode == "160000":
			continue
		default:
			out[p] = restFlatFile{sha: e.SHA, mode: e.Mode}
		}
	}
}

// restTreeOf returns the root tree sha of a commit, or "" when unknown.
func (s *Server) restTreeOf(commitSHA string) string {
	commit := s.restParseCommit(commitSHA)
	if commit == nil {
		return ""
	}
	return commit.Tree
}

// restMergeBase returns a merge-base of a and b: the first ancestor of b
// (depth-first) that is also an ancestor of a. Exact on the linear
// histories the fixtures build.
func (s *Server) restMergeBase(a, b string) (string, bool) {
	ancestors := make(map[string]bool)
	stack := []string{a}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if ancestors[c] {
			continue
		}
		ancestors[c] = true
		commit := s.restParseCommit(c)
		if commit == nil {
			continue
		}
		stack = append(stack, commit.Parents...)
	}
	seen := make(map[string]bool)
	stack = []string{b}
	for len(stack) > 0 {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[c] {
			continue
		}
		seen[c] = true
		if ancestors[c] {
			return c, true
		}
		commit := s.restParseCommit(c)
		if commit == nil {
			continue
		}
		stack = append(stack, commit.Parents...)
	}
	return "", false
}

// restLiveTip returns the live tip of a branch, or fallback when the
// branch no longer exists.
func (s *Server) restLiveTip(repo *store.Repo, branch, fallback string) string {
	if sha, ok := s.store.GetRef(repo.Owner, repo.Name, "refs/heads/"+branch); ok {
		return sha
	}
	return fallback
}

// prFileChange is one entry of a pull-request diff.
type prFileChange struct {
	filename  string
	status    string // "added" | "modified" | "removed"
	additions int
	deletions int
}

// restPRDiff computes the merge-base diff between the PR's base tip and
// head tip: every changed path with its status and line counts, sorted
// by filename. Shared with W4's GraphQL pullRequest.files.
func (s *Server) restPRDiff(repo *store.Repo, pr *store.PullRequest) ([]prFileChange, error) {
	headSHA := s.restLiveTip(repo, pr.HeadRef, pr.HeadSHA)
	baseSHA := s.restLiveTip(repo, pr.BaseRef, pr.BaseSHA)
	mb, ok := s.restMergeBase(headSHA, baseSHA)
	baseMap := make(map[string]restFlatFile)
	if ok {
		s.restFlattenTree(s.restTreeOf(mb), "", baseMap)
	}
	headMap := make(map[string]restFlatFile)
	s.restFlattenTree(s.restTreeOf(headSHA), "", headMap)
	paths := make([]string, 0, len(headMap)+len(baseMap))
	seen := make(map[string]bool, len(headMap)+len(baseMap))
	for p := range headMap {
		seen[p] = true
		paths = append(paths, p)
	}
	for p := range baseMap {
		if !seen[p] {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	out := make([]prFileChange, 0, len(paths))
	for _, p := range paths {
		oldFile, inOld := baseMap[p]
		newFile, inNew := headMap[p]
		switch {
		case inNew && !inOld:
			out = append(out, prFileChange{
				filename:  p,
				status:    "added",
				additions: restCountLines(s.restBlobBytes(newFile.sha)),
			})
		case inOld && !inNew:
			out = append(out, prFileChange{
				filename:  p,
				status:    "removed",
				deletions: restCountLines(s.restBlobBytes(oldFile.sha)),
			})
		case oldFile.sha != newFile.sha:
			add, del := restLineDiff(s.restBlobBytes(oldFile.sha), s.restBlobBytes(newFile.sha))
			out = append(out, prFileChange{
				filename:  p,
				status:    "modified",
				additions: add,
				deletions: del,
			})
		}
	}
	return out, nil
}

// restBlobBytes returns a blob's bytes, or nil when unknown.
func (s *Server) restBlobBytes(sha string) []byte {
	data, typ, ok := s.store.GetObject(sha)
	if !ok || typ != git.ObjBlob {
		return nil
	}
	return data
}

// restCountLines counts the lines in blob bytes: the newline count, plus
// one when the content is non-empty and does not end with a newline.
func restCountLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// restSplitLines splits blob bytes into lines (a trailing newline does
// not produce an extra empty line).
func restSplitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// restLineDiff counts added and removed lines between two blob versions
// by multiset difference: a line present in both counts for neither.
func restLineDiff(oldData, newData []byte) (add, del int) {
	counts := make(map[string]int)
	for _, line := range restSplitLines(oldData) {
		counts[string(line)]++
	}
	for _, line := range restSplitLines(newData) {
		key := string(line)
		if counts[key] > 0 {
			counts[key]--
		} else {
			add++
		}
	}
	for _, c := range counts {
		del += c
	}
	return add, del
}

// restBuildTreeFromMap builds git trees for a flat path -> file map and
// returns the root tree sha. All trees are git-sorted, hashed and stored.
func (s *Server) restBuildTreeFromMap(paths map[string]restFlatFile) string {
	return s.restBuildTreeLevel(paths, "")
}

func (s *Server) restBuildTreeLevel(paths map[string]restFlatFile, prefix string) string {
	var entries []git.TreeEntry
	subdirs := make(map[string]bool)
	for p, f := range paths {
		rest := p[len(prefix):]
		if i := strings.IndexByte(rest, '/'); i < 0 {
			entries = append(entries, git.TreeEntry{Mode: f.mode, Name: rest, SHA: f.sha})
		} else {
			subdirs[rest[:i]] = true
		}
	}
	for dir := range subdirs {
		sub := s.restBuildTreeLevel(paths, prefix+dir+"/")
		entries = append(entries, git.TreeEntry{Mode: "40000", Name: dir, SHA: sub})
	}
	git.SortTreeEntries(entries)
	data := git.BuildTree(entries)
	sha := git.HashObject(git.ObjTree, data)
	s.store.PutObject(sha, git.ObjTree, data)
	return sha
}

// squashMerge performs the SQUASH-ONLY merge of pr onto its base branch
// and returns the new commit sha. It is the one merge implementation for
// all surfaces: REST PUT /pulls/{n}/merge, GraphQL mergePullRequest and
// MCP merge_pull_request all call it.
//
// Semantics: three-way file-level conflict detection against the
// merge-base; on success exactly ONE squash commit is created on the
// base branch whose tree is the base tree plus the PR's net changes,
// the base ref advances to it, and the PR closes with merged=true,
// merged_at set and merge_commit_sha equal to the squash commit sha.
func (s *Server) squashMerge(repo *store.Repo, pr *store.PullRequest) (string, error) {
	if pr.Merged {
		return "", &restMergeError{status: 405, msg: "Pull request is already merged"}
	}
	if pr.State != "open" {
		return "", &restMergeError{status: 405, msg: "Pull request is closed"}
	}
	headSHA := s.restLiveTip(repo, pr.HeadRef, pr.HeadSHA)
	baseTip := s.restLiveTip(repo, pr.BaseRef, pr.BaseSHA)
	mb, ok := s.restMergeBase(headSHA, baseTip)
	mbMap := make(map[string]restFlatFile)
	if ok {
		s.restFlattenTree(s.restTreeOf(mb), "", mbMap)
	}
	headMap := make(map[string]restFlatFile)
	s.restFlattenTree(s.restTreeOf(headSHA), "", headMap)
	baseMap := make(map[string]restFlatFile)
	s.restFlattenTree(s.restTreeOf(baseTip), "", baseMap)

	// Three-way file-level conflict detection: for every path the head
	// changed against the merge-base, a conflict exists when the base
	// also changed it and to different content.
	for p, headFile := range headMap {
		mbFile, inMB := mbMap[p]
		if inMB && mbFile.sha == headFile.sha {
			continue // head did not change this path
		}
		baseFile, inBase := baseMap[p]
		baseSHA := ""
		if inBase {
			baseSHA = baseFile.sha
		}
		mbSHA := ""
		if inMB {
			mbSHA = mbFile.sha
		}
		if baseSHA != mbSHA && baseSHA != headFile.sha {
			return "", &restMergeError{status: 405, msg: "Merge conflict in " + p}
		}
	}
	for p := range mbMap {
		if _, inHead := headMap[p]; inHead {
			continue
		}
		// Head deleted this path; a base modification of it conflicts.
		baseFile, inBase := baseMap[p]
		if inBase && baseFile.sha != mbMap[p].sha {
			return "", &restMergeError{status: 405, msg: "Merge conflict in " + p}
		}
	}

	// Squash tree: the base tree plus the PR's net changes.
	result := make(map[string]restFlatFile, len(baseMap)+len(headMap))
	for p, f := range baseMap {
		result[p] = f
	}
	for p, headFile := range headMap {
		if mbFile, inMB := mbMap[p]; inMB && mbFile.sha == headFile.sha {
			continue
		}
		result[p] = headFile
	}
	for p := range mbMap {
		if _, inHead := headMap[p]; !inHead {
			delete(result, p)
		}
	}
	newTree := s.restBuildTreeFromMap(result)
	ident := s.restCommitterIdent()
	message := pr.Title + " (#" + strconv.Itoa(pr.Number) + ")"
	commitBytes := git.BuildCommit(newTree, []string{baseTip}, ident, ident, message)
	commitSHA := git.HashObject(git.ObjCommit, commitBytes)
	s.store.PutObject(commitSHA, git.ObjCommit, commitBytes)
	if err := s.store.SetRef(repo.Owner, repo.Name, "refs/heads/"+pr.BaseRef, commitSHA); err != nil {
		return "", err
	}
	now := s.store.Now()
	if _, err := s.store.UpdatePR(repo.Key(), pr.Number, func(p *store.PullRequest) error {
		p.State = "closed"
		p.Merged = true
		p.MergeCommitSHA = commitSHA
		p.MergedAt = &now
		p.ClosedAt = &now
		return nil
	}); err != nil {
		return "", err
	}
	return commitSHA, nil
}
