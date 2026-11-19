// Package httpapi is the forge's HTTP surface: routing, auth, and the
// four surfaces (git smart HTTP, REST v3, GraphQL v4, MCP), served
// over the raw-TCP transport in internal/transport.
//
// Server implements transport.Handler. Auth is checked here, before
// routing: every route except GET /healthz requires
// Authorization: Bearer <MAKEFUN_SHOP_TOKEN>. The four surfaces live
// in their own files, written by their owners (INTERFACE.md §1):
//
//	gitproto.go  W2  s.handleGit      smart HTTP
//	rest.go      W3  s.handleREST     REST v3
//	graphql.go   W4  s.handleGraphQL  GraphQL v4
//	mcp.go       W4  s.handleMCP      MCP JSON-RPC
//
// This file also provides the shared helpers those handlers use:
// jsonResponse, jsonError, and requestID.
package httpapi

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"forge/internal/store"
	"forge/internal/transport"
)

// Server is the forge's HTTP server: routing + auth + the four
// surfaces. It implements transport.Handler.
type Server struct {
	store *store.Store
	token string
	seq   atomic.Uint64 // request-id sequence, mixed into requestID
}

// NewServer builds the server over the given store. The bearer token
// is read once, here, from env MAKEFUN_SHOP_TOKEN.
func NewServer(s *store.Store) *Server {
	return &Server{store: s, token: os.Getenv("MAKEFUN_SHOP_TOKEN")}
}

// Store returns the store this server serves.
func (s *Server) Store() *store.Store { return s.store }

// Handle dispatches one request. Auth is checked HERE, before routing
// (except GET /healthz): a missing or wrong Bearer token answers 401
// JSON {"message": "Requires authentication"}. Every response carries
// X-GitHub-Request-Id (set here when the handler did not set it).
func (s *Server) Handle(req *transport.Request) *transport.Response {
	// /healthz is the ONLY unauthenticated route.
	if req.Method == "GET" && req.Path == "/healthz" {
		return s.withRequestID(req, jsonResponse(200, []byte(`{"ok": true}`)))
	}
	if req.Header("authorization") != "Bearer "+s.token {
		return s.withRequestID(req, jsonError(401, "Requires authentication"))
	}

	var resp *transport.Response
	switch {
	case req.Path == "/api/graphql":
		resp = s.handleGraphQL(req)
	case req.Path == "/mcp":
		resp = s.handleMCP(req)
	case isRESTPath(req.Path):
		resp = s.handleREST(req)
	case isGitPath(req.Path):
		resp = s.handleGit(req)
	default:
		resp = jsonError(404, "Not Found")
	}
	return s.withRequestID(req, resp)
}

// withRequestID stamps X-GitHub-Request-Id on the response when the
// handler did not, and guards against a nil response or a zero status.
func (s *Server) withRequestID(req *transport.Request, resp *transport.Response) *transport.Response {
	if resp == nil {
		resp = jsonError(500, "Internal Server Error")
	}
	if resp.Status == 0 {
		resp.Status = 500
	}
	if resp.Headers == nil {
		resp.Headers = make(map[string]string, 1)
	}
	if _, ok := resp.Headers["X-GitHub-Request-Id"]; !ok {
		resp.Headers["X-GitHub-Request-Id"] = s.requestID(req)
	}
	return resp
}

// isRESTPath reports whether path belongs to the REST v3 surface:
// the /api/v3/ prefix (and the bare /api/v3), /user/, /repos/, and
// the API root /.
func isRESTPath(path string) bool {
	switch {
	case path == "/api/v3" || strings.HasPrefix(path, "/api/v3/"):
		return true
	case path == "/user" || strings.HasPrefix(path, "/user/"):
		return true
	case strings.HasPrefix(path, "/repos/"):
		return true
	case path == "/":
		return true
	}
	return false
}

// isGitPath reports whether path is a git smart-HTTP route:
// /{owner}/{repo}/info/refs, /{owner}/{repo}/git-upload-pack, or
// /{owner}/{repo}/git-receive-pack. The kit's git client requests the
// repo as /{owner}/{repo}.git (git-client.ts repoPath), so a ".git"
// suffix on the repo segment is accepted as well; handleGit strips it
// when it resolves the repo.
func isGitPath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	rest := path[1:]
	// Owner: the first segment, non-empty.
	i := strings.IndexByte(rest, '/')
	if i <= 0 {
		return false
	}
	rest = rest[i+1:]
	// Repo: the second segment, non-empty.
	j := strings.IndexByte(rest, '/')
	if j <= 0 {
		return false
	}
	switch rest[j+1:] {
	case "info/refs", "git-upload-pack", "git-receive-pack":
		return true
	}
	return false
}

// jsonResponse builds a JSON response with the given status and body
// bytes (already-encoded JSON, no trailing newline added). The
// transport supplies Content-Type: application/json; charset=utf-8
// when the response carries no Content-Type header.
func jsonResponse(status int, body []byte) *transport.Response {
	return &transport.Response{Status: status, Body: body}
}

// jsonError builds a JSON error response: {"message": msg}. The
// message is JSON-escaped, so dynamic messages stay valid JSON.
func jsonError(status int, msg string) *transport.Response {
	quoted, _ := json.Marshal(msg) // a string always marshals
	body := make([]byte, 0, len(quoted)+13)
	body = append(body, `{"message":`...)
	body = append(body, quoted...)
	body = append(body, '}')
	return jsonResponse(status, body)
}

// requestID returns a 16-hex-char request id for
// X-GitHub-Request-Id. Deterministic per (method, path, seq): an
// FNV-1a hash of the method, the path, and a per-server atomic
// counter. No randomness, no wall clock.
func (s *Server) requestID(req *transport.Request) string {
	seq := s.seq.Add(1)
	h := fnv.New64a()
	_, _ = h.Write([]byte(req.Method))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(req.Path))
	_, _ = h.Write([]byte{0})
	var tmp [8]byte
	_, _ = h.Write(strconv.AppendUint(tmp[:0], seq, 10))
	var sum [8]byte
	binary.BigEndian.PutUint64(sum[:], h.Sum64())
	return hex.EncodeToString(sum[:])
}
