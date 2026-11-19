// MCP (Model Context Protocol) JSON-RPC 2.0 server over Streamable HTTP
// at POST /mcp.
//
// Two protocol eras, one handler (mcp-client.ts is the contract —
// follow it, not the public MCP spec):
//   - modern 2026-07-28: server/discover returns identity, capabilities
//     and supportedVersions in one request; no handshake, no session.
//   - legacy 2025-11-25 and earlier: initialize + notifications/initialized.
//
// Both eras share tools/list and tools/call.
//
// Wire rules:
//   - One plain JSON body per request (no SSE).
//   - Echo the request id EXACTLY (string, number, or null).
//   - Notifications (no id) get HTTP 202 with an empty body.
//   - Malformed JSON -> HTTP 400 + JSON-RPC -32700.
//   - Unknown method -> -32601; unknown tool -> -32602; missing tool
//     arguments -> -32602; domain errors -> a result with isError: true.
//   - tools/list is byte-identical across calls: it is marshaled once
//     from a fixed struct slice at init and the bytes are reused.
//   - Auth is checked by the dispatcher before this runs.
package httpapi

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"

	"forge/internal/store"
	"forge/internal/transport"
)

// mcpServerName/mcpServerVersion are the server identity reported by
// server/discover and initialize. Both must be non-empty.
const (
	mcpServerName    = "forge"
	mcpServerVersion = "1.0.0"
)

// mcpSupportedVersions lists the revisions the server speaks, newest
// first. The client picks 2026-07-28 when listed.
var mcpSupportedVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// ---------------------------------------------------------------- tools

// mcpSchemaProp is one JSON Schema property of a tool inputSchema.
type mcpSchemaProp struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// mcpSchemaProperty is one named property, in declaration order.
type mcpSchemaProperty struct {
	Name string
	Prop mcpSchemaProp
}

// mcpSchemaProperties is an ORDERED property list. It marshals as a JSON
// object in slice order — never from a Go map, whose iteration order is
// random and would break tools/list byte-identity.
type mcpSchemaProperties []mcpSchemaProperty

// MarshalJSON writes the properties as an object, in slice order.
func (p mcpSchemaProperties) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, prop := range p {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, err := json.Marshal(prop.Name)
		if err != nil {
			return nil, err
		}
		val, err := json.Marshal(prop.Prop)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(val)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// mcpInputSchema is a tool's inputSchema: type object, ordered
// properties, and the required list. Every required property must be
// fillable by the suite — when in doubt, require less.
type mcpInputSchema struct {
	Type       string              `json:"type"`
	Properties mcpSchemaProperties `json:"properties"`
	Required   []string            `json:"required,omitempty"`
}

// mcpTool is one tool as tools/list answers it.
type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema mcpInputSchema `json:"inputSchema"`
}

// mcpTools is the fixed tool list (github-mcp-server names). The order
// is the order tools/list reports, every time.
var mcpTools = []mcpTool{
	{
		Name:        "create_repo",
		Description: "Create a new repository owned by the authenticated user.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: mcpSchemaProperties{
				{Name: "name", Prop: mcpSchemaProp{Type: "string", Description: "The repository name."}},
				{Name: "description", Prop: mcpSchemaProp{Type: "string", Description: "A short description of the repository."}},
				{Name: "private", Prop: mcpSchemaProp{Type: "boolean", Description: "Whether the repository is private."}},
			},
			Required: []string{"name"},
		},
	},
	{
		Name:        "get_repo",
		Description: "Get a repository by owner and name.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: mcpSchemaProperties{
				{Name: "owner", Prop: mcpSchemaProp{Type: "string", Description: "The repository owner."}},
				{Name: "repo", Prop: mcpSchemaProp{Type: "string", Description: "The repository name."}},
			},
			Required: []string{"owner", "repo"},
		},
	},
	{
		Name:        "create_issue",
		Description: "Create an issue in a repository.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: mcpSchemaProperties{
				{Name: "owner", Prop: mcpSchemaProp{Type: "string", Description: "The repository owner."}},
				{Name: "repo", Prop: mcpSchemaProp{Type: "string", Description: "The repository name."}},
				{Name: "title", Prop: mcpSchemaProp{Type: "string", Description: "The issue title."}},
				{Name: "body", Prop: mcpSchemaProp{Type: "string", Description: "The issue body."}},
			},
			Required: []string{"owner", "repo", "title"},
		},
	},
	{
		Name:        "list_issues",
		Description: "List issues in a repository.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: mcpSchemaProperties{
				{Name: "owner", Prop: mcpSchemaProp{Type: "string", Description: "The repository owner."}},
				{Name: "repo", Prop: mcpSchemaProp{Type: "string", Description: "The repository name."}},
				{Name: "state", Prop: mcpSchemaProp{Type: "string", Description: "Filter by state: open, closed, or all."}},
			},
			Required: []string{"owner", "repo"},
		},
	},
	{
		Name:        "create_pull_request",
		Description: "Create a pull request in a repository.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: mcpSchemaProperties{
				{Name: "owner", Prop: mcpSchemaProp{Type: "string", Description: "The repository owner."}},
				{Name: "repo", Prop: mcpSchemaProp{Type: "string", Description: "The repository name."}},
				{Name: "title", Prop: mcpSchemaProp{Type: "string", Description: "The pull request title."}},
				{Name: "head", Prop: mcpSchemaProp{Type: "string", Description: "The head branch name."}},
				{Name: "base", Prop: mcpSchemaProp{Type: "string", Description: "The base branch name."}},
				{Name: "body", Prop: mcpSchemaProp{Type: "string", Description: "The pull request body."}},
			},
			Required: []string{"owner", "repo", "title", "head", "base"},
		},
	},
	{
		Name:        "merge_pull_request",
		Description: "Merge a pull request with a squash merge.",
		InputSchema: mcpInputSchema{
			Type: "object",
			Properties: mcpSchemaProperties{
				{Name: "owner", Prop: mcpSchemaProp{Type: "string", Description: "The repository owner."}},
				{Name: "repo", Prop: mcpSchemaProp{Type: "string", Description: "The repository name."}},
				{Name: "pull_number", Prop: mcpSchemaProp{Type: "integer", Description: "The pull request number."}},
			},
			Required: []string{"owner", "repo", "pull_number"},
		},
	},
}

// mcpCapabilities is the capabilities object: tools present (an empty
// object — the client only requires it to be a record).
type mcpCapabilities struct {
	Tools struct{} `json:"tools"`
}

// mcpServerInfo is the server identity object.
type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpDiscoverMeta carries the server identity under the 2026-07-28
// _meta key (the client reads _meta first, then the loose serverInfo).
type mcpDiscoverMeta struct {
	ServerInfo mcpServerInfo `json:"io.modelcontextprotocol/serverInfo"`
}

// mcpDiscoverResult is the server/discover result.
type mcpDiscoverResult struct {
	SupportedVersions []string        `json:"supportedVersions"`
	Capabilities      mcpCapabilities `json:"capabilities"`
	ServerInfo        mcpServerInfo   `json:"serverInfo"`
	Instructions      string          `json:"instructions"`
	Meta              mcpDiscoverMeta `json:"_meta"`
}

// mcpInitializePayload is the initialize result.
type mcpInitializePayload struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    mcpCapabilities `json:"capabilities"`
	ServerInfo      mcpServerInfo   `json:"serverInfo"`
}

// Precomputed, byte-stable response fragments. tools/list reuses the
// same bytes on every call, so two answers are identical by construction.
var (
	mcpToolsJSON          []byte
	mcpToolsListResult    []byte
	mcpDiscoverResultJSON []byte
)

func init() {
	info := mcpServerInfo{Name: mcpServerName, Version: mcpServerVersion}
	mcpToolsJSON, _ = json.Marshal(mcpTools)
	mcpToolsListResult = append([]byte(`{"tools":`), mcpToolsJSON...)
	mcpToolsListResult = append(mcpToolsListResult, '}')
	mcpDiscoverResultJSON, _ = json.Marshal(mcpDiscoverResult{
		SupportedVersions: mcpSupportedVersions,
		Capabilities:      mcpCapabilities{},
		ServerInfo:        info,
		Instructions:      "A GitHub-compatible git forge: repositories, issues and pull requests.",
		Meta:              mcpDiscoverMeta{ServerInfo: info},
	})
}

// ---------------------------------------------------------------- wire

// mcpRequest is one JSON-RPC request. ID is a pointer so a missing id
// (a notification) is distinguishable from an explicit null id, and a
// RawMessage so the id is echoed byte-for-byte.
type mcpRequest struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params"`
}

// handleMCP serves POST /mcp: JSON-RPC 2.0 over Streamable HTTP.
// Auth is checked by the dispatcher before this runs.
func (s *Server) handleMCP(req *transport.Request) *transport.Response {
	var msg mcpRequest
	if err := json.Unmarshal(req.Body, &msg); err != nil {
		// Malformed JSON: HTTP 400 + JSON-RPC -32700, id null.
		return jsonResponse(400, mcpErrorResponse(nil, -32700, "Parse error"))
	}
	// Notifications carry no id: acknowledge, never answer JSON-RPC.
	if msg.ID == nil {
		return jsonResponse(202, nil)
	}
	id := *msg.ID
	switch msg.Method {
	case "server/discover":
		return jsonResponse(200, mcpResultResponse(id, mcpDiscoverResultJSON))
	case "initialize":
		return jsonResponse(200, mcpResultResponse(id, mcpInitializeResult(msg.Params)))
	case "tools/list":
		return jsonResponse(200, mcpResultResponse(id, mcpToolsListResult))
	case "tools/call":
		return s.mcpToolsCall(id, msg.Params)
	case "ping":
		return jsonResponse(200, mcpResultResponse(id, []byte("{}")))
	default:
		return jsonResponse(200, mcpErrorResponse(id, -32601, "Method not found: "+msg.Method))
	}
}

// mcpResultResponse builds {"jsonrpc":"2.0","id":<echoed>,"result":<result>}.
func mcpResultResponse(id json.RawMessage, result []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"jsonrpc":"2.0","id":`)
	if len(id) == 0 {
		buf.WriteString("null")
	} else {
		buf.Write(id)
	}
	buf.WriteString(`,"result":`)
	buf.Write(result)
	buf.WriteByte('}')
	return buf.Bytes()
}

// mcpErrorResponse builds a JSON-RPC error response. A nil id encodes
// as null (the parse-error case: the id could not be read).
func mcpErrorResponse(id json.RawMessage, code int, message string) []byte {
	msg, _ := json.Marshal(message)
	var buf bytes.Buffer
	buf.WriteString(`{"jsonrpc":"2.0","id":`)
	if len(id) == 0 {
		buf.WriteString("null")
	} else {
		buf.Write(id)
	}
	buf.WriteString(`,"error":{"code":`)
	buf.WriteString(strconv.Itoa(code))
	buf.WriteString(`,"message":`)
	buf.Write(msg)
	buf.WriteString(`}}`)
	return buf.Bytes()
}

// mcpInitializeResult answers the legacy handshake: echo the offered
// revision when it is one this server speaks, else the newest legacy
// revision. Never -32602 a well-formed initialize.
func mcpInitializeResult(params json.RawMessage) []byte {
	version := "2025-11-25"
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(params) > 0 {
		_ = json.Unmarshal(params, &p)
	}
	for _, v := range mcpSupportedVersions {
		if p.ProtocolVersion == v {
			version = v
			break
		}
	}
	out, _ := json.Marshal(mcpInitializePayload{
		ProtocolVersion: version,
		Capabilities:    mcpCapabilities{},
		ServerInfo:      mcpServerInfo{Name: mcpServerName, Version: mcpServerVersion},
	})
	return out
}

// ---------------------------------------------------------------- tools/call

// mcpCallOutcome is one tool call's answer: either a result object
// (errCode 0) or a JSON-RPC error.
type mcpCallOutcome struct {
	result  []byte
	errCode int
	errMsg  string
}

// mcpToolsCall dispatches a tools/call request.
func (s *Server) mcpToolsCall(id json.RawMessage, params json.RawMessage) *transport.Response {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return jsonResponse(200, mcpErrorResponse(id, -32602, "Invalid params"))
		}
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}
	var outcome mcpCallOutcome
	switch p.Name {
	case "create_repo":
		outcome = s.mcpCreateRepo(p.Arguments)
	case "get_repo":
		outcome = s.mcpGetRepo(p.Arguments)
	case "create_issue":
		outcome = s.mcpCreateIssue(p.Arguments)
	case "list_issues":
		outcome = s.mcpListIssues(p.Arguments)
	case "create_pull_request":
		outcome = s.mcpCreatePullRequest(p.Arguments)
	case "merge_pull_request":
		outcome = s.mcpMergePullRequest(p.Arguments)
	default:
		return jsonResponse(200, mcpErrorResponse(id, -32602, "Unknown tool: "+p.Name))
	}
	if outcome.errCode != 0 {
		return jsonResponse(200, mcpErrorResponse(id, outcome.errCode, outcome.errMsg))
	}
	return jsonResponse(200, mcpResultResponse(id, outcome.result))
}

// mcpTextResult renders a tool result whose text block is the JSON of
// value and whose structuredContent is the same value. The checks read
// both: resultJson prefers structuredContent, list_issues scans the text.
func mcpTextResult(value any) []byte {
	raw, _ := json.Marshal(value)
	text, _ := json.Marshal(string(raw))
	var buf bytes.Buffer
	buf.WriteString(`{"content":[{"type":"text","text":`)
	buf.Write(text)
	buf.WriteString(`}],"structuredContent":`)
	buf.Write(raw)
	buf.WriteByte('}')
	return buf.Bytes()
}

// mcpToolErrorResult renders a tool execution failure: isError true
// with a text reason.
func mcpToolErrorResult(message string) []byte {
	text, _ := json.Marshal(message)
	var buf bytes.Buffer
	buf.WriteString(`{"content":[{"type":"text","text":`)
	buf.Write(text)
	buf.WriteString(`}],"isError":true}`)
	return buf.Bytes()
}

// mcpMissingArg is the -32602 outcome for a missing required argument.
func mcpMissingArg(tool, arg string) mcpCallOutcome {
	return mcpCallOutcome{errCode: -32602, errMsg: tool + ": missing required argument: " + arg}
}

// mcpArgString reads a string argument ("" when absent or not a string).
func mcpArgString(args map[string]any, name string) string {
	v, _ := args[name].(string)
	return v
}

// mcpArgBool reads a boolean argument (false when absent or not a bool).
func mcpArgBool(args map[string]any, name string) bool {
	v, _ := args[name].(bool)
	return v
}

// mcpArgInt reads an integer argument, accepting a JSON number or a
// decimal string.
func mcpArgInt(args map[string]any, name string) (int, bool) {
	switch v := args[name].(type) {
	case float64:
		return int(v), true
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// mcpRepoObject is the repository JSON a tool result carries. full_name
// is "owner/name": the rest-parity check parses it to find the repo
// over REST.
func mcpRepoObject(repo *store.Repo) map[string]any {
	return map[string]any{
		"id":             repo.ID,
		"name":           repo.Name,
		"full_name":      repo.FullName(),
		"owner":          map[string]any{"login": repo.Owner},
		"private":        repo.Private,
		"description":    repo.Description,
		"default_branch": repo.DefaultBranch,
		"created_at":     repo.CreatedAt.Format(time.RFC3339),
		"updated_at":     repo.UpdatedAt.Format(time.RFC3339),
	}
}

// mcpIssueObject is the issue JSON a tool result carries.
func mcpIssueObject(issue *store.Issue) map[string]any {
	return map[string]any{
		"id":         issue.ID,
		"number":     issue.Number,
		"title":      issue.Title,
		"body":       issue.Body,
		"state":      issue.State,
		"user":       map[string]any{"login": issue.UserLogin},
		"created_at": issue.CreatedAt.Format(time.RFC3339),
		"updated_at": issue.UpdatedAt.Format(time.RFC3339),
	}
}

// mcpRepoArgs extracts the owner/repo pair every repo-scoped tool
// needs, or the -32602 outcome naming the missing argument.
func mcpRepoArgs(tool string, args map[string]any) (owner, repo string, outcome mcpCallOutcome, ok bool) {
	owner = mcpArgString(args, "owner")
	if owner == "" {
		return "", "", mcpMissingArg(tool, "owner"), false
	}
	repo = mcpArgString(args, "repo")
	if repo == "" {
		return "", "", mcpMissingArg(tool, "repo"), false
	}
	return owner, repo, mcpCallOutcome{}, true
}

func (s *Server) mcpCreateRepo(args map[string]any) mcpCallOutcome {
	name := mcpArgString(args, "name")
	if name == "" {
		return mcpMissingArg("create_repo", "name")
	}
	owner := s.tokenOwnerLogin()
	repo, err := s.store.CreateRepo(owner, name, store.RepoOptions{
		Description: mcpArgString(args, "description"),
		Private:     mcpArgBool(args, "private"),
	})
	if err != nil {
		if err == store.ErrRepoExists {
			return mcpCallOutcome{result: mcpToolErrorResult("repository already exists: " + owner + "/" + name)}
		}
		return mcpCallOutcome{result: mcpToolErrorResult(err.Error())}
	}
	return mcpCallOutcome{result: mcpTextResult(mcpRepoObject(repo))}
}

func (s *Server) mcpGetRepo(args map[string]any) mcpCallOutcome {
	owner, name, outcome, ok := mcpRepoArgs("get_repo", args)
	if !ok {
		return outcome
	}
	repo, err := s.store.GetRepo(owner, name)
	if err != nil {
		return mcpCallOutcome{result: mcpToolErrorResult("repository not found: " + owner + "/" + name)}
	}
	return mcpCallOutcome{result: mcpTextResult(mcpRepoObject(repo))}
}

func (s *Server) mcpCreateIssue(args map[string]any) mcpCallOutcome {
	owner, name, outcome, ok := mcpRepoArgs("create_issue", args)
	if !ok {
		return outcome
	}
	title := mcpArgString(args, "title")
	if title == "" {
		return mcpMissingArg("create_issue", "title")
	}
	if _, err := s.store.GetRepo(owner, name); err != nil {
		return mcpCallOutcome{result: mcpToolErrorResult("repository not found: " + owner + "/" + name)}
	}
	issue, err := s.store.CreateIssue(store.RepoKey(owner, name), title, mcpArgString(args, "body"), nil)
	if err != nil {
		return mcpCallOutcome{result: mcpToolErrorResult(err.Error())}
	}
	return mcpCallOutcome{result: mcpTextResult(mcpIssueObject(issue))}
}

func (s *Server) mcpListIssues(args map[string]any) mcpCallOutcome {
	owner, name, outcome, ok := mcpRepoArgs("list_issues", args)
	if !ok {
		return outcome
	}
	if _, err := s.store.GetRepo(owner, name); err != nil {
		return mcpCallOutcome{result: mcpToolErrorResult("repository not found: " + owner + "/" + name)}
	}
	state := mcpArgString(args, "state")
	issues := s.store.ListIssues(store.RepoKey(owner, name))
	list := make([]any, 0, len(issues))
	for _, issue := range issues {
		if state == "open" && issue.State != "open" {
			continue
		}
		if state == "closed" && issue.State != "closed" {
			continue
		}
		list = append(list, mcpIssueObject(issue))
	}
	return mcpCallOutcome{result: mcpTextResult(list)}
}

func (s *Server) mcpCreatePullRequest(args map[string]any) mcpCallOutcome {
	owner, name, outcome, ok := mcpRepoArgs("create_pull_request", args)
	if !ok {
		return outcome
	}
	title := mcpArgString(args, "title")
	if title == "" {
		return mcpMissingArg("create_pull_request", "title")
	}
	head := mcpArgString(args, "head")
	if head == "" {
		return mcpMissingArg("create_pull_request", "head")
	}
	base := mcpArgString(args, "base")
	if base == "" {
		return mcpMissingArg("create_pull_request", "base")
	}
	if _, err := s.store.GetRepo(owner, name); err != nil {
		return mcpCallOutcome{result: mcpToolErrorResult("repository not found: " + owner + "/" + name)}
	}
	headSHA, _ := s.store.GetRef(owner, name, "refs/heads/"+head)
	baseSHA, _ := s.store.GetRef(owner, name, "refs/heads/"+base)
	pr, err := s.store.CreatePR(store.RepoKey(owner, name), store.PROptions{
		Title:   title,
		Body:    mcpArgString(args, "body"),
		HeadRef: head,
		HeadSHA: headSHA,
		BaseRef: base,
		BaseSHA: baseSHA,
	})
	if err != nil {
		return mcpCallOutcome{result: mcpToolErrorResult(err.Error())}
	}
	return mcpCallOutcome{result: mcpTextResult(map[string]any{
		"id":          pr.ID,
		"number":      pr.Number,
		"pull_number": pr.Number,
		"title":       pr.Title,
		"body":        pr.Body,
		"state":       pr.State,
		"head":        map[string]any{"ref": pr.HeadRef},
		"base":        map[string]any{"ref": pr.BaseRef},
		"merged":      false,
		"created_at":  pr.CreatedAt.Format(time.RFC3339),
		"updated_at":  pr.UpdatedAt.Format(time.RFC3339),
	})}
}

func (s *Server) mcpMergePullRequest(args map[string]any) mcpCallOutcome {
	owner, name, outcome, ok := mcpRepoArgs("merge_pull_request", args)
	if !ok {
		return outcome
	}
	number, ok := mcpArgInt(args, "pull_number")
	if !ok {
		return mcpMissingArg("merge_pull_request", "pull_number")
	}
	key := store.RepoKey(owner, name)
	if _, ok := s.store.GetPR(key, number); !ok {
		return mcpCallOutcome{result: mcpToolErrorResult("pull request not found")}
	}
	updated, err := s.store.UpdatePR(key, number, func(pr *store.PullRequest) error {
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
		return mcpCallOutcome{result: mcpToolErrorResult(err.Error())}
	}
	return mcpCallOutcome{result: mcpTextResult(map[string]any{
		"id":          updated.ID,
		"number":      updated.Number,
		"pull_number": updated.Number,
		"title":       updated.Title,
		"state":       updated.State,
		"merged":      true,
	})}
}
