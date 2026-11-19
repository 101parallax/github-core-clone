# Interface Contract — github-core-clone-01 build (v1)

**Purpose:** W2/W3/W4/W6 work in PARALLEL on different files. This document is the
single source of truth for every type and function signature they share. If the
contract and a worker's guess disagree, THE CONTRACT WINS. Do not improvise
shared signatures.

**Repo:** `~/workspace/makefun/github-core-clone-01/repo/` (module `forge`, Go 1.24,
zero dependencies). Go binary: `~/workspace/tools/go1.24/bin/go`.
**Kit:** `~/workspace/makefun/github-core-clone-01/ghc-kit/github-core-clone-01-kit/`
**Docs:** `GHC-RESEARCH.md` (strategy + perf playbook), `GHC-DESIGN.md` (architecture),
`build-logs/CHECK-INVENTORY.md` (all 120 checks).

---

## 1. File ownership (NO two workers edit the same file)

| File | Owner | Notes |
|---|---|---|
| `go/internal/transport/transport.go` | W6 | Raw-TCP HTTP/1.1 server (NEW file) |
| `go/internal/httpapi/http.go` | W6 | REWRITE: Server + dispatcher on raw transport |
| `go/cmd/forge/main.go` | W6 | EDIT: use transport server, bind 0.0.0.0 |
| `go/internal/git/git.go` | W2 | Object model (NEW file) |
| `go/internal/git/pack.go` | W2 | pkt-line, pack read/write, deltas (NEW file) |
| `go/internal/httpapi/gitproto.go` | W2 | Smart-HTTP handlers (NEW file) |
| `go/internal/store/store.go` | W2 | EDIT ONLY: add per-repo atomic gen (see §5). Nothing else. |
| `go/internal/httpapi/rest.go` | W3 | REST v3 dispatcher (NEW file) |
| `go/internal/httpapi/json.go` | W3 | Hand-rolled JSON encoder (NEW file) |
| `go/internal/httpapi/graphql.go` | W4 | GraphQL parser + executor (NEW file) |
| `go/internal/httpapi/mcp.go` | W4 | MCP JSON-RPC + 6 tools (NEW file) |
| `main.ts`, `README.md`, `forge` binary | W5 | Later, after W2/W3/W4/W6 finish |

W3 and W4 do NOT touch store.go. W2 does NOT touch http.go/rest.go/graphql.go/mcp.go.
W6 does NOT touch git.go/pack.go/gitproto.go/rest.go/json.go/graphql.go/mcp.go/store.go.

---

## 2. transport package (W6 writes, everyone uses)

```go
package transport

// Request is one parsed HTTP request. Handlers must not retain it past
// the call (the transport reuses it per connection).
type Request struct {
    Method  string            // "GET", "POST", "PUT", "PATCH", "DELETE"
    Path    string            // decoded path, no query, e.g. "/repos/ada/foo/issues"
    Query   string            // raw query string, no leading "?", e.g. "page=2&per_page=10"
    Headers map[string]string // lower-cased header names -> first value
    Body    []byte            // request body (nil when empty)
}

// Header returns the header value for name (case-insensitive), or "".
func (r *Request) Header(name string) string

// QueryParam returns the first value of query key, or "" when absent.
func (r *Request) QueryParam(key string) string

// Response is one HTTP response.
type Response struct {
    Status  int               // e.g. 200
    Headers map[string]string // response headers; Content-Type defaults to
                              // "application/json; charset=utf-8" when unset
                              // (handlers set it explicitly for git bytes)
    Body    []byte            // response body (nil = empty body)
}

// Handler handles one request and returns its response.
type Handler interface {
    Handle(req *Request) *Response
}

// Server is the raw-TCP HTTP/1.1 server: keep-alive, Content-Length
// framing both ways, chunked request bodies, Expect: 100-continue,
// pipelining tolerated. No net/http on the serving path.
type Server struct { /* W6's internals */ }

// NewServer builds a server over handler h.
func NewServer(h Handler) *Server

// Serve accepts connections on l until Close is called. Blocks.
func (s *Server) Serve(l net.Listener) error

// Close stops accepting and closes idle connections.
func (s *Server) Close() error
```

Transport requirements (W6):
- Bind is done by main.go; Serve takes an already-bound `net.Listener`.
- Every response carries `Content-Length` (no chunked responses), single `Write`.
- Keep-alive: serve multiple requests per connection; never send `Connection: close`
  unless the client asked for it.
- Parse ONLY the headers the forge reads (authorization, content-length,
  content-type, accept, user-agent, host, expect, transfer-encoding).
- First-byte dispatch on header names (P1-8). Pool per-connection buffers.
- Never log per request. Never panic on malformed input (400 + close).

---

## 3. httpapi Server + dispatcher (W6 writes http.go)

```go
package httpapi

// Server is the forge's HTTP server: routing + auth + the four surfaces.
// It implements transport.Handler.
type Server struct {
    store *store.Store
    // W6's internals (dispatch tables, token, etc.)
}

// NewServer builds the server over the given store.
func NewServer(s *store.Store) *Server

// Store returns the store this server serves.
func (s *Server) Store() *store.Store

// Handle dispatches one request. Auth is checked HERE, before routing
// (except GET /healthz): missing/wrong Bearer token -> 401 JSON
// {"message": "Requires authentication"}. The token is read once at
// startup from env MAKEFUN_SHOP_TOKEN.
func (s *Server) Handle(req *transport.Request) *transport.Response
```

**Dispatcher routing (exact):**
| Path | Handler (method on *Server) | Owner |
|---|---|---|
| `GET /healthz` | inline: 200 `{"ok": true}`, NO auth | W6 |
| `/api/graphql` | `s.handleGraphQL(req)` | W4 |
| `/mcp` | `s.handleMCP(req)` | W4 |
| `/api/v3/` prefix, `/user/`, `/repos/`, `/` (API root) | `s.handleREST(req)` | W3 |
| `/{owner}/{repo}/info/refs`, `/{owner}/{repo}/git-upload-pack`, `/{owner}/{repo}/git-receive-pack` | `s.handleGit(req)` | W2 |
| anything else | JSON 404 `{"message": "Not Found"}` | W6 |

**Handler method signatures (W2/W3/W4 define these in their own files):**
```go
func (s *Server) handleGit(req *transport.Request) *transport.Response       // W2, gitproto.go
func (s *Server) handleREST(req *transport.Request) *transport.Response      // W3, rest.go
func (s *Server) handleGraphQL(req *transport.Request) *transport.Response   // W4, graphql.go
func (s *Server) handleMCP(req *transport.Request) *transport.Response       // W4, mcp.go
```

**Shared helpers (W6 provides in http.go; W2/W3/W4 use them):**
```go
// jsonResponse builds a JSON response with the given status and body bytes
// (already-encoded JSON, no trailing newline added).
func jsonResponse(status int, body []byte) *transport.Response
// jsonError builds a JSON error response: {"message": msg}.
func jsonError(status int, msg string) *transport.Response
// requestID returns a 16-hex-char request id for X-GitHub-Request-Id.
// Deterministic per (method, path, seq) — no randomness.
func (s *Server) requestID(req *transport.Request) string
```
Every REST/GraphQL/MCP response MUST carry header `X-GitHub-Request-Id`
(non-empty). W6's dispatcher sets it on every response if the handler
did not. (Git smart-HTTP responses: set it too when cheap; not checked.)

**Auth details:**
- Token source: env `MAKEFUN_SHOP_TOKEN`, read once in `NewServer`.
- Accept: `Authorization: Bearer <token>` (exact match). Anything else → 401.
- 401 body: `{"message": "Requires authentication"}`.
- /healthz is the ONLY unauthenticated route.

---

## 4. main.go changes (W6)

- Bind `0.0.0.0:0` (NOT 127.0.0.1:0 — the env dials the pod IP).
- Replace `http.Server{Handler: srv}` with `transport.NewServer(srv)` and
  `Serve(listener)`. Shutdown calls `transportServer.Close()`.
- Keep register/poll logic EXACTLY as-is (net/http client is fine there —
  not a hot path). Keep the retry/backoff constants.
- Keep `store.NewStore()` + `httpapi.NewServer(st)` construction order.

---

## 5. Store extensions (W2 ONLY)

W1's store API is complete (see store.go). W2 adds ONE thing for the
git cache (P0-3/P0-8):

```go
// RepoGen returns the repo's mutation generation (atomic load, NO lock).
// It increments on every SetRef/DeleteRef for that repo. Cache keys
// include the gen so stale entries are never served.
func (s *Store) RepoGen(owner, name string) uint64
```

Implementation: a `map[string]*uint64` (repo key → generation counter,
allocated at CreateRepo), bumped with `sync/atomic` in SetRef/DeleteRef.
Do NOT change any other store method's signature or behavior. Do NOT
change the global RWMutex (v1 correctness first; per-repo sharding is
a v2 optimization if profiling demands it).

---

## 6. JSON encoder (W3 writes json.go, W4 may use it)

```go
// Hand-rolled JSON for hot response types. MUST byte-match encoding/json
// output (including HTML escaping of <>& as \u003c \u003e \u0026).
// W3: write encodeIssue, encodeRepo, encodePR, encodeComment,
// encodeUser, encodeLabel, encodeRef + a string escaper. Verify with a
// test that byte-compares against json.Marshal on an adversarial corpus.
```

W4 (GraphQL/MCP) MAY use encoding/json (not timed workloads) or the
hand-rolled encoder — W4's choice. MCP `tools/list` MUST be emitted
from a fixed struct slice, NEVER from a Go map (byte-identical across calls).

---

## 7. Git package API (W2 defines, gitproto.go + rest.go use it)

W2 defines these in `internal/git/`; rest.go (W3) needs commit/tree
building for the contents API and PR merge, so W2 must export:

```go
package git

// Object types.
const (
    ObjCommit = "commit"
    ObjTree   = "tree"
    ObjBlob   = "blob"
    ObjTag    = "tag"
)

// HashObject returns the SHA-1 hex id of a git object (type + len + NUL + data).
func HashObject(objType string, data []byte) string

// Commit is a parsed commit object.
type Commit struct {
    Tree      string   // tree sha
    Parents   []string // parent shas, in order
    Author    string   // raw author line (name <email> ts tz)
    Committer string   // raw committer line
    Message   string   // commit message (after the blank line)
    Raw       []byte   // the exact stored bytes
}

// ParseCommit parses commit bytes. Returns error on malformed input.
func ParseCommit(data []byte) (*Commit, error)

// BuildCommit serializes a commit (tree, parents, author, committer,
// message) to canonical git bytes.
func BuildCommit(tree string, parents []string, author, committer, message string) []byte

// TreeEntry is one entry in a tree object.
type TreeEntry struct {
    Mode string // e.g. "100644", "40000"
    Name string
    SHA  string
}

// ParseTree parses tree bytes into entries (in stored order).
func ParseTree(data []byte) ([]TreeEntry, error)

// BuildTree serializes entries to canonical git bytes (entries MUST be
// git-sorted by name, dirs as if suffixed with "/").
func BuildTree(entries []TreeEntry) []byte

// SortTreeEntries sorts entries in git order (in place).
func SortTreeEntries(entries []TreeEntry)

// Pack writing (W2's pack.go): BuildPack assembles a plain (undeltified)
// pack from objects. Pack reading: ReadPack parses a pack, resolving
// OFS_DELTA and REF_DELTA in ONE unified DFS walk. Exact signatures are
// W2's choice — gitproto.go is also W2's, so only W2 consumes them.
// (rest.go does NOT touch packs; it builds objects via HashObject +
// store.PutObject.)
```

---

## 8. Verification (W5, after all workers finish)

- `go vet ./...` clean. `go build` → binary <8 MiB, executable, committed +x.
- Practice trials (3) via kit local runner: 120/120 checks, 3 consecutive runs.
- `go build -race` passes the check phase.
- RSS <512 MiB during `--perf`. No writes outside /tmp.
- `makefun bundle --dry-run` finds all build sessions.

---

## 9. Rules (non-negotiable)

- NEVER read `b1-upload/` Go source. NEVER read any other entrant's repo.
  Read ONLY: GHC-RESEARCH.md, GHC-DESIGN.md, this contract, the kit's
  conformance tests / clients / starter, and public documentation.
- Write ALL code fresh via write/edit. NO `cp`, NO clone of code, NO paste.
- No wall clock / randomness in stored data. Deterministic output.
- Commit your files when done (each worker commits its own files on main;
  pull first, resolve conflicts by keeping both sides' files — files are
  disjoint by §1, so conflicts should not happen).
