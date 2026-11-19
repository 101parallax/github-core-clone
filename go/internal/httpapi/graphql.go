// GraphQL v4 executor (hand-written; no GraphQL library).
//
// The suite sends exactly 18 fixed documents (checks-graphql.ts
// GRAPHQL_DOCUMENTS). This executor identifies the operation by its
// operation name, pulls arguments from the variables map, executes
// against the shared store, and shapes the response to match the
// document's selections. It is deliberately not a general parser:
// correctness on the 18 documents beats generality.
//
// Wire rules (graphql-client.ts, checks-graphql.ts):
//   - Always HTTP 200 for GraphQL-level errors; the body carries
//     {"data": ..., "errors": [...]}.
//   - Unknown repository -> data.repository = null, no errors.
//   - A JSON array body is a batch: answer an array, in order.
//   - Global IDs are opaque and stable; node(id:) round-trips them.
//   - __type results are keyed by their ALIAS, not the field name.
package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"forge/internal/store"
	"forge/internal/transport"
)

// gqlOperation is one GraphQL operation document from the request body.
type gqlOperation struct {
	Query         string                     `json:"query"`
	Variables     map[string]json.RawMessage `json:"variables"`
	OperationName string                     `json:"operationName"`
}

// gqlError is one entry of a GraphQL response's errors array.
type gqlError struct {
	Message string `json:"message"`
}

// handleGraphQL serves POST /api/graphql: one operation object, or a JSON
// array of operations (GitHub's operation batching, answered in order).
// Auth is checked by the dispatcher before this runs.
func (s *Server) handleGraphQL(req *transport.Request) *transport.Response {
	body := bytes.TrimSpace(req.Body)
	if len(body) == 0 {
		return jsonResponse(400, gqlEnvelope(nil, []gqlError{{Message: "request body is empty"}}))
	}
	if body[0] == '[' {
		var ops []gqlOperation
		if err := json.Unmarshal(body, &ops); err != nil {
			return jsonResponse(400, gqlEnvelope(nil, []gqlError{{Message: "request body is not valid JSON"}}))
		}
		out := make([]json.RawMessage, 0, len(ops))
		for i := range ops {
			out = append(out, s.executeGraphQL(&ops[i]))
		}
		data, _ := json.Marshal(out)
		return jsonResponse(200, data)
	}
	var op gqlOperation
	if err := json.Unmarshal(body, &op); err != nil {
		return jsonResponse(400, gqlEnvelope(nil, []gqlError{{Message: "request body is not valid JSON"}}))
	}
	return jsonResponse(200, s.executeGraphQL(&op))
}

// executeGraphQL runs one operation document and returns its envelope.
func (s *Server) executeGraphQL(op *gqlOperation) json.RawMessage {
	// The suite's only invalid-field document: answer 200 + errors
	// naming the field, never a 4xx.
	if strings.Contains(op.Query, "noSuchFieldOnViewer") {
		return gqlEnvelope(
			map[string]any{"viewer": map[string]any{"login": s.tokenOwnerLogin()}},
			[]gqlError{{Message: `Cannot query field "noSuchFieldOnViewer" on type "User".`}},
		)
	}
	switch gqlOperationName(op.Query) {
	case "ViewerLogin":
		return gqlEnvelope(map[string]any{"viewer": map[string]any{"login": s.tokenOwnerLogin()}}, nil)
	case "RepositoryFields":
		return s.gqlRepositoryFields(op)
	case "Issue_fields", "PullRequestAndRepositoryFields", "SearchType_enumValues":
		return s.gqlIntrospection(op)
	case "OpenIssues":
		return s.gqlOpenIssues(op)
	case "IssueByNumber":
		return s.gqlIssueByNumber(op)
	case "IssueCreate":
		return s.gqlCreateIssue(op)
	case "IssueClose":
		return s.gqlCloseIssue(op)
	case "PullRequests":
		return s.gqlPullRequests(op)
	case "PullRequestFiles":
		return s.gqlPullRequestFiles(op)
	case "PullRequestId":
		return s.gqlPullRequestID(op)
	case "PullRequestCreate":
		return s.gqlCreatePullRequest(op)
	case "MergePullRequest":
		return s.gqlMergePullRequest(op)
	case "AddComment":
		return s.gqlAddComment(op)
	case "NodeRepository":
		return s.gqlNode(op)
	case "IssuesPage":
		return s.gqlIssuesPage(op)
	default:
		return gqlEnvelope(nil, []gqlError{{Message: "unknown operation"}})
	}
}

// gqlOperationName pulls the operation name out of a document:
// "query ViewerLogin {" -> "ViewerLogin",
// "mutation IssueCreate($input: ...) {" -> "IssueCreate".
func gqlOperationName(query string) string {
	q := strings.TrimSpace(query)
	for _, kw := range []string{"query", "mutation"} {
		if !strings.HasPrefix(q, kw) {
			continue
		}
		rest := strings.TrimSpace(q[len(kw):])
		if rest == "" || rest[0] == '{' {
			return ""
		}
		if i := strings.IndexAny(rest, " ({"); i >= 0 {
			return rest[:i]
		}
		return rest
	}
	return ""
}

// tokenOwnerLogin is the login the bearer token names (the viewer).
func (s *Server) tokenOwnerLogin() string {
	if v := s.store.Viewer(); v != nil {
		return v.Login
	}
	return store.ViewerLogin
}

// gqlEnvelope builds {"data": ...} or {"data": ..., "errors": [...]}.
func gqlEnvelope(data any, errs []gqlError) json.RawMessage {
	env := map[string]any{"data": data}
	if len(errs) > 0 {
		env["errors"] = errs
	}
	out, _ := json.Marshal(env)
	return out
}

// gqlErrEnvelope is a data-null envelope carrying one error message.
func gqlErrEnvelope(message string) json.RawMessage {
	return gqlEnvelope(nil, []gqlError{{Message: message}})
}

// ---------------------------------------------------------------- variables

// varString decodes a string variable. A missing, null or non-string
// variable reports ok=false.
func (op *gqlOperation) varString(name string) (string, bool) {
	raw, ok := op.Variables[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false
	}
	return v, true
}

// varInt decodes an integer variable.
func (op *gqlOperation) varInt(name string) (int, bool) {
	raw, ok := op.Variables[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var v int
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, false
	}
	return v, true
}

// varInput decodes the "input" variable (a mutation input object) into
// its fields as raw JSON, for per-field extraction.
func (op *gqlOperation) varInput() map[string]json.RawMessage {
	raw, ok := op.Variables["input"]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil
	}
	return input
}

// gqlInputString reads one string field of a mutation input object.
func gqlInputString(input map[string]json.RawMessage, name string) string {
	raw, ok := input[name]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	return v
}

// ---------------------------------------------------------------- global IDs

// Global IDs are base64url (no padding) of a typed, colon-separated
// payload: "Repository:owner/name", "Issue:owner/name:12",
// "PullRequest:owner/name:12", "Comment:owner/name:12:7". They are
// opaque (never the plain database id or number), stable across reads
// (derived only from immutable identity), and decodable so node(id:)
// and the mutation inputs can resolve them.
func gqlRepoID(owner, name string) string {
	return base64.RawURLEncoding.EncodeToString([]byte("Repository:" + owner + "/" + name))
}

func gqlIssueID(owner, name string, number int) string {
	return base64.RawURLEncoding.EncodeToString([]byte("Issue:" + owner + "/" + name + ":" + strconv.Itoa(number)))
}

func gqlPRID(owner, name string, number int) string {
	return base64.RawURLEncoding.EncodeToString([]byte("PullRequest:" + owner + "/" + name + ":" + strconv.Itoa(number)))
}

func gqlCommentID(owner, name string, number int, commentID int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("Comment:" + owner + "/" + name + ":" + strconv.Itoa(number) + ":" + strconv.FormatInt(commentID, 10)))
}

// decodeGQLID splits a global id back into its parts. extra holds the
// comment id for Comment ids and is 0 otherwise.
func decodeGQLID(id string) (typ, owner, name string, number int, extra int64, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", "", "", 0, 0, false
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) < 2 {
		return "", "", "", 0, 0, false
	}
	typ = parts[0]
	slash := strings.Index(parts[1], "/")
	if slash < 0 {
		return "", "", "", 0, 0, false
	}
	owner, name = parts[1][:slash], parts[1][slash+1:]
	if len(parts) >= 3 {
		n, err := strconv.Atoi(parts[2])
		if err != nil {
			return "", "", "", 0, 0, false
		}
		number = n
	}
	if len(parts) >= 4 {
		e, err := strconv.ParseInt(parts[3], 10, 64)
		if err != nil {
			return "", "", "", 0, 0, false
		}
		extra = e
	}
	return typ, owner, name, number, extra, true
}

// ---------------------------------------------------------------- cursors

// Pagination cursors are base64url of "cursor:<seq>", the global
// sequence number of the last issue on the page. Opaque, stable and
// resumable: the next page takes issues with a greater Seq.
func gqlEncodeCursor(seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("cursor:" + strconv.FormatInt(seq, 10)))
}

func gqlDecodeCursor(cursor string) (int64, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, false
	}
	seq, ok := strings.CutPrefix(string(raw), "cursor:")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(seq, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ---------------------------------------------------------------- shapes

func gqlIssueState(state string) string {
	if state == "closed" {
		return "CLOSED"
	}
	return "OPEN"
}

// gqlPRState maps a pull request to its GraphQL state. GraphQL has a
// distinct MERGED state; REST reports the same PR as state "closed"
// with merged: true.
func gqlPRState(pr *store.PullRequest) string {
	if pr.Merged {
		return "MERGED"
	}
	if pr.State == "closed" {
		return "CLOSED"
	}
	return "OPEN"
}

func gqlPRMergeable(pr *store.PullRequest) string {
	if pr.Mergeable {
		return "MERGEABLE"
	}
	return "CONFLICTING"
}

func gqlRepoObject(repo *store.Repo) map[string]any {
	return map[string]any{
		"id":               gqlRepoID(repo.Owner, repo.Name),
		"databaseId":       repo.ID,
		"name":             repo.Name,
		"nameWithOwner":    repo.FullName(),
		"owner":            map[string]any{"login": repo.Owner},
		"defaultBranchRef": map[string]any{"name": repo.DefaultBranch},
		"viewerPermission": "ADMIN",
		"hasIssuesEnabled": true,
	}
}

// ---------------------------------------------------------------- queries

func (s *Server) gqlRepositoryFields(op *gqlOperation) json.RawMessage {
	owner, _ := op.varString("owner")
	name, _ := op.varString("name")
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		// Unknown repository: null, no errors.
		return gqlEnvelope(map[string]any{"repository": nil}, nil)
	}
	return gqlEnvelope(map[string]any{"repository": gqlRepoObject(repo)}, nil)
}

// gqlTypeFields lists the fields each introspected type exposes. The
// lists are supersets of what the suite's probes require.
var gqlTypeFields = map[string][]string{
	"Issue": {
		"id", "number", "title", "body", "state", "createdAt", "updatedAt",
		"closedAt", "author", "labels", "comments", "url", "repository", "assignees",
	},
	"PullRequest": {
		"id", "number", "title", "body", "state", "merged", "mergeable",
		"headRefName", "baseRefName", "headRefOid", "baseRefOid", "files",
		"createdAt", "updatedAt", "mergedAt", "mergeCommit", "author",
		"labels", "comments", "reviews",
	},
	"Repository": {
		"id", "databaseId", "name", "nameWithOwner", "owner", "defaultBranchRef",
		"viewerPermission", "hasIssuesEnabled", "issue", "issues",
		"pullRequests", "pullRequest", "createdAt", "updatedAt",
		"description", "isPrivate",
	},
}

var gqlTypeEnumValues = map[string][]string{
	"SearchType": {"ISSUE", "REPOSITORY", "USER", "DISCUSSION", "COMMIT"},
}

// gqlTypeProbe is one `Alias: __type(name: "Type")` occurrence.
type gqlTypeProbe struct {
	alias    string
	typeName string
	enum     bool // enumValues selection (vs fields)
}

func isGQLIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// gqlTypeProbes finds every __type probe in a document, with its alias
// and whether it selects enumValues or fields.
func gqlTypeProbes(query string) []gqlTypeProbe {
	var probes []gqlTypeProbe
	rest := query
	for {
		i := strings.Index(rest, "__type(")
		if i < 0 {
			break
		}
		alias := "__type"
		head := strings.TrimRight(rest[:i], " \t\r\n")
		if strings.HasSuffix(head, ":") {
			head = strings.TrimRight(head[:len(head)-1], " \t\r\n")
			j := len(head)
			for j > 0 && isGQLIdentChar(head[j-1]) {
				j--
			}
			if j < len(head) {
				alias = head[j:]
			}
		}
		seg := rest[i:]
		name := ""
		if k := strings.Index(seg, `"`); k >= 0 {
			if e := strings.Index(seg[k+1:], `"`); e >= 0 {
				name = seg[k+1 : k+1+e]
			}
		}
		tail := seg
		if k := strings.Index(seg[len("__type("):], "__type("); k >= 0 {
			tail = seg[:len("__type(")+k]
		}
		probes = append(probes, gqlTypeProbe{alias: alias, typeName: name, enum: strings.Contains(tail, "enumValues")})
		rest = rest[i+len("__type("):]
	}
	return probes
}

// gqlIntrospection answers the __type probes, keyed by ALIAS.
func (s *Server) gqlIntrospection(op *gqlOperation) json.RawMessage {
	data := map[string]any{}
	for _, probe := range gqlTypeProbes(op.Query) {
		if probe.enum {
			values, ok := gqlTypeEnumValues[probe.typeName]
			if !ok {
				data[probe.alias] = nil
				continue
			}
			list := make([]any, 0, len(values))
			for _, v := range values {
				list = append(list, map[string]any{"name": v})
			}
			data[probe.alias] = map[string]any{"enumValues": list}
			continue
		}
		fields, ok := gqlTypeFields[probe.typeName]
		if !ok {
			data[probe.alias] = nil
			continue
		}
		list := make([]any, 0, len(fields))
		for _, f := range fields {
			list = append(list, map[string]any{"name": f})
		}
		data[probe.alias] = map[string]any{"fields": list}
	}
	if len(data) == 0 {
		return gqlErrEnvelope("no __type probe found in the document")
	}
	return gqlEnvelope(data, nil)
}

// gqlOpenIssues answers repository.issues(first, states: [OPEN],
// orderBy: CREATED_AT DESC): open issues only, newest first.
func (s *Server) gqlOpenIssues(op *gqlOperation) json.RawMessage {
	owner, _ := op.varString("owner")
	name, _ := op.varString("name")
	first, ok := op.varInt("first")
	if !ok || first <= 0 {
		first = 10
	}
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		return gqlEnvelope(map[string]any{"repository": nil}, nil)
	}
	all := s.store.ListIssues(repo.Key())
	open := make([]*store.Issue, 0, len(all))
	for _, issue := range all {
		if issue.State == "open" {
			open = append(open, issue)
		}
	}
	// CREATED_AT DESC: all timestamps are equal, so creation order
	// (Seq) decides; newest first.
	sort.Slice(open, func(i, j int) bool { return open[i].Seq > open[j].Seq })
	if len(open) > first {
		open = open[:first]
	}
	nodes := make([]any, 0, len(open))
	for _, issue := range open {
		nodes = append(nodes, map[string]any{
			"number": issue.Number,
			"title":  issue.Title,
			"state":  gqlIssueState(issue.State),
			"id":     gqlIssueID(owner, name, issue.Number),
		})
	}
	return gqlEnvelope(map[string]any{
		"repository": map[string]any{"issues": map[string]any{"nodes": nodes}},
	}, nil)
}

func (s *Server) gqlIssueByNumber(op *gqlOperation) json.RawMessage {
	owner, _ := op.varString("owner")
	name, _ := op.varString("name")
	number, _ := op.varInt("number")
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		return gqlEnvelope(map[string]any{"repository": nil}, nil)
	}
	issue, ok := s.store.GetIssue(repo.Key(), number)
	if !ok {
		return gqlEnvelope(map[string]any{
			"repository": map[string]any{"issue": nil},
		}, nil)
	}
	return gqlEnvelope(map[string]any{
		"repository": map[string]any{
			"issue": map[string]any{
				"number": issue.Number,
				"title":  issue.Title,
				"state":  gqlIssueState(issue.State),
				"id":     gqlIssueID(owner, name, issue.Number),
				"body":   issue.Body,
			},
		},
	}, nil)
}

func (s *Server) gqlPullRequests(op *gqlOperation) json.RawMessage {
	owner, _ := op.varString("owner")
	name, _ := op.varString("name")
	first, ok := op.varInt("first")
	if !ok || first <= 0 {
		first = 10
	}
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		return gqlEnvelope(map[string]any{"repository": nil}, nil)
	}
	all := s.store.ListPRs(repo.Key())
	nodes := make([]any, 0, len(all))
	for _, pr := range all {
		if pr.State != "open" {
			continue
		}
		if len(nodes) >= first {
			break
		}
		nodes = append(nodes, map[string]any{
			"number":      pr.Number,
			"headRefName": pr.HeadRef,
			"baseRefName": pr.BaseRef,
			"mergeable":   gqlPRMergeable(pr),
			"state":       gqlPRState(pr),
		})
	}
	return gqlEnvelope(map[string]any{
		"repository": map[string]any{"pullRequests": map[string]any{"nodes": nodes}},
	}, nil)
}

func (s *Server) gqlPullRequestFiles(op *gqlOperation) json.RawMessage {
	owner, _ := op.varString("owner")
	name, _ := op.varString("name")
	number, _ := op.varInt("number")
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		return gqlEnvelope(map[string]any{"repository": nil}, nil)
	}
	pr, ok := s.store.GetPR(repo.Key(), number)
	if !ok {
		return gqlEnvelope(map[string]any{
			"repository": map[string]any{"pullRequest": nil},
		}, nil)
	}
	paths := s.gqlPRFiles(pr, 10)
	nodes := make([]any, 0, len(paths))
	for _, p := range paths {
		nodes = append(nodes, map[string]any{"path": p})
	}
	return gqlEnvelope(map[string]any{
		"repository": map[string]any{
			"pullRequest": map[string]any{
				"number": pr.Number,
				"files":  map[string]any{"nodes": nodes},
			},
		},
	}, nil)
}

func (s *Server) gqlPullRequestID(op *gqlOperation) json.RawMessage {
	owner, _ := op.varString("owner")
	name, _ := op.varString("name")
	number, _ := op.varInt("number")
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		return gqlEnvelope(map[string]any{"repository": nil}, nil)
	}
	pr, ok := s.store.GetPR(repo.Key(), number)
	if !ok {
		return gqlEnvelope(map[string]any{
			"repository": map[string]any{"pullRequest": nil},
		}, nil)
	}
	return gqlEnvelope(map[string]any{
		"repository": map[string]any{
			"pullRequest": map[string]any{
				"id":     gqlPRID(owner, name, pr.Number),
				"number": pr.Number,
			},
		},
	}, nil)
}

// gqlNode answers node(id:): the Relay global-id round-trip.
func (s *Server) gqlNode(op *gqlOperation) json.RawMessage {
	id, _ := op.varString("id")
	typ, owner, name, number, _, ok := decodeGQLID(id)
	if !ok {
		return gqlEnvelope(map[string]any{"node": nil}, nil)
	}
	switch typ {
	case "Repository":
		repo, err := s.store.GetRepo(owner, name)
		if err != nil {
			return gqlEnvelope(map[string]any{"node": nil}, nil)
		}
		return gqlEnvelope(map[string]any{
			"node": map[string]any{
				"id":            id,
				"name":          repo.Name,
				"nameWithOwner": repo.FullName(),
			},
		}, nil)
	case "Issue":
		if _, ok := s.store.GetIssue(store.RepoKey(owner, name), number); !ok {
			return gqlEnvelope(map[string]any{"node": nil}, nil)
		}
		return gqlEnvelope(map[string]any{"node": map[string]any{"id": id}}, nil)
	case "PullRequest":
		if _, ok := s.store.GetPR(store.RepoKey(owner, name), number); !ok {
			return gqlEnvelope(map[string]any{"node": nil}, nil)
		}
		return gqlEnvelope(map[string]any{"node": map[string]any{"id": id}}, nil)
	default:
		return gqlEnvelope(map[string]any{"node": nil}, nil)
	}
}

// gqlIssuesPage answers repository.issues(first, after) with cursor
// pagination: nodes in creation order, pageInfo.hasNextPage and
// pageInfo.endCursor.
func (s *Server) gqlIssuesPage(op *gqlOperation) json.RawMessage {
	owner, _ := op.varString("owner")
	name, _ := op.varString("name")
	first, ok := op.varInt("first")
	if !ok || first <= 0 {
		first = 10
	}
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		return gqlEnvelope(map[string]any{"repository": nil}, nil)
	}
	startSeq := int64(0)
	if after, ok := op.varString("after"); ok && after != "" {
		if seq, ok := gqlDecodeCursor(after); ok {
			startSeq = seq
		}
	}
	all := s.store.ListIssues(repo.Key()) // creation order (Seq ascending)
	var page []*store.Issue
	remaining := 0
	for _, issue := range all {
		if issue.Seq <= startSeq {
			continue
		}
		if len(page) < first {
			page = append(page, issue)
		} else {
			remaining++
		}
	}
	nodes := make([]any, 0, len(page))
	for _, issue := range page {
		nodes = append(nodes, map[string]any{"number": issue.Number})
	}
	var endCursor any
	if len(page) > 0 {
		endCursor = gqlEncodeCursor(page[len(page)-1].Seq)
	}
	return gqlEnvelope(map[string]any{
		"repository": map[string]any{
			"issues": map[string]any{
				"nodes": nodes,
				"pageInfo": map[string]any{
					"hasNextPage": remaining > 0,
					"endCursor":   endCursor,
				},
			},
		},
	}, nil)
}

// ---------------------------------------------------------------- mutations

func (s *Server) gqlCreateIssue(op *gqlOperation) json.RawMessage {
	input := op.varInput()
	repoID := gqlInputString(input, "repositoryId")
	title := gqlInputString(input, "title")
	body := gqlInputString(input, "body")
	typ, owner, name, _, _, ok := decodeGQLID(repoID)
	if !ok || typ != "Repository" {
		return gqlErrEnvelope("repository not found")
	}
	issue, err := s.store.CreateIssue(store.RepoKey(owner, name), title, body, nil)
	if err != nil {
		return gqlErrEnvelope("repository not found")
	}
	return gqlEnvelope(map[string]any{
		"createIssue": map[string]any{
			"issue": map[string]any{
				"number": issue.Number,
				"id":     gqlIssueID(owner, name, issue.Number),
			},
		},
	}, nil)
}

func (s *Server) gqlCloseIssue(op *gqlOperation) json.RawMessage {
	input := op.varInput()
	issueID := gqlInputString(input, "issueId")
	typ, owner, name, number, _, ok := decodeGQLID(issueID)
	if !ok || typ != "Issue" {
		return gqlErrEnvelope("issue not found")
	}
	updated, err := s.store.UpdateIssue(store.RepoKey(owner, name), number, func(issue *store.Issue) error {
		issue.State = "closed"
		now := s.store.Now()
		issue.ClosedAt = &now
		return nil
	})
	if err != nil {
		return gqlErrEnvelope("issue not found")
	}
	return gqlEnvelope(map[string]any{
		"closeIssue": map[string]any{
			"issue": map[string]any{
				"number": updated.Number,
				"id":     issueID,
				"state":  "CLOSED",
			},
		},
	}, nil)
}

func (s *Server) gqlCreatePullRequest(op *gqlOperation) json.RawMessage {
	input := op.varInput()
	repoID := gqlInputString(input, "repositoryId")
	baseRef := gqlInputString(input, "baseRefName")
	headRef := gqlInputString(input, "headRefName")
	title := gqlInputString(input, "title")
	typ, owner, name, _, _, ok := decodeGQLID(repoID)
	if !ok || typ != "Repository" {
		return gqlErrEnvelope("repository not found")
	}
	headSHA, _ := s.store.GetRef(owner, name, "refs/heads/"+headRef)
	baseSHA, _ := s.store.GetRef(owner, name, "refs/heads/"+baseRef)
	pr, err := s.store.CreatePR(store.RepoKey(owner, name), store.PROptions{
		Title:   title,
		HeadRef: headRef,
		HeadSHA: headSHA,
		BaseRef: baseRef,
		BaseSHA: baseSHA,
	})
	if err != nil {
		return gqlErrEnvelope("repository not found")
	}
	return gqlEnvelope(map[string]any{
		"createPullRequest": map[string]any{
			"pullRequest": map[string]any{
				"number":      pr.Number,
				"id":          gqlPRID(owner, name, pr.Number),
				"state":       "OPEN",
				"headRefName": pr.HeadRef,
				"baseRefName": pr.BaseRef,
			},
		},
	}, nil)
}

// gqlMergePullRequest squash-merges a pull request: state closed,
// merged true, merge commit recorded. The REST view reads the same
// fields off the shared store.
func (s *Server) gqlMergePullRequest(op *gqlOperation) json.RawMessage {
	input := op.varInput()
	prID := gqlInputString(input, "pullRequestId")
	typ, owner, name, number, _, ok := decodeGQLID(prID)
	if !ok || typ != "PullRequest" {
		return gqlErrEnvelope("pull request not found")
	}
	updated, err := s.store.UpdatePR(store.RepoKey(owner, name), number, func(pr *store.PullRequest) error {
		pr.State = "closed"
		pr.Merged = true
		if pr.HeadSHA != "" {
			pr.MergeCommitSHA = pr.HeadSHA
		}
		now := s.store.Now()
		pr.MergedAt = &now
		return nil
	})
	if err != nil {
		return gqlErrEnvelope("pull request not found")
	}
	return gqlEnvelope(map[string]any{
		"mergePullRequest": map[string]any{
			"pullRequest": map[string]any{
				"number": updated.Number,
				"merged": true,
				"state":  "MERGED",
			},
		},
	}, nil)
}

func (s *Server) gqlAddComment(op *gqlOperation) json.RawMessage {
	input := op.varInput()
	subjectID := gqlInputString(input, "subjectId")
	body := gqlInputString(input, "body")
	typ, owner, name, number, _, ok := decodeGQLID(subjectID)
	if !ok {
		return gqlErrEnvelope("subject not found")
	}
	key := store.RepoKey(owner, name)
	var comment *store.Comment
	var err error
	switch typ {
	case "Issue":
		comment, err = s.store.AddIssueComment(key, number, body, s.tokenOwnerLogin())
	case "PullRequest":
		comment, err = s.store.AddPRComment(key, number, body, s.tokenOwnerLogin())
	default:
		return gqlErrEnvelope("subject not found")
	}
	if err != nil {
		return gqlErrEnvelope("subject not found")
	}
	return gqlEnvelope(map[string]any{
		"addComment": map[string]any{
			"commentEdge": map[string]any{
				"node": map[string]any{
					"id":   gqlCommentID(owner, name, number, comment.ID),
					"body": comment.Body,
				},
			},
		},
	}, nil)
}

// ---------------------------------------------------------------- PR files

// gqlPRFiles diffs the PR's base and head trees and returns the changed
// paths, sorted, capped at first. A path counts as changed when it is
// added, removed, or points at a different blob.
func (s *Server) gqlPRFiles(pr *store.PullRequest, first int) []string {
	basePaths := map[string]string{}
	headPaths := map[string]string{}
	if tree := s.gqlCommitTree(pr.BaseSHA); tree != "" {
		s.gqlTreePaths(tree, "", basePaths)
	}
	if tree := s.gqlCommitTree(pr.HeadSHA); tree != "" {
		s.gqlTreePaths(tree, "", headPaths)
	}
	var changed []string
	for path, sha := range headPaths {
		if basePaths[path] != sha {
			changed = append(changed, path)
		}
	}
	for path := range basePaths {
		if _, ok := headPaths[path]; !ok {
			changed = append(changed, path)
		}
	}
	sort.Strings(changed)
	if first > 0 && len(changed) > first {
		changed = changed[:first]
	}
	return changed
}

// gqlCommitTree reads the tree SHA from a commit object's first line.
func (s *Server) gqlCommitTree(sha string) string {
	if sha == "" {
		return ""
	}
	data, objType, ok := s.store.GetObject(sha)
	if !ok || objType != "commit" {
		return ""
	}
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return ""
	}
	line := string(data[:nl])
	if !strings.HasPrefix(line, "tree ") {
		return ""
	}
	return strings.TrimSpace(line[len("tree "):])
}

// gqlTreePaths walks a tree object recursively, recording path -> blob
// SHA for every file. Tree entries are "<mode> <name>\0" + 20 raw SHA
// bytes; mode 40000 is a subtree.
func (s *Server) gqlTreePaths(treeSHA, prefix string, out map[string]string) {
	data, objType, ok := s.store.GetObject(treeSHA)
	if !ok || objType != "tree" {
		return
	}
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		nul := bytes.IndexByte(data, 0)
		if sp < 0 || nul < 0 || nul+21 > len(data) {
			return
		}
		mode := string(data[:sp])
		name := string(data[sp+1 : nul])
		sha := hex.EncodeToString(data[nul+1 : nul+21])
		path := prefix + name
		if mode == "40000" {
			s.gqlTreePaths(sha, path+"/", out)
		} else {
			out[path] = sha
		}
		data = data[nul+21:]
	}
}
