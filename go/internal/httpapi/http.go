// Package httpapi is the forge's HTTP surface: routing, auth, and the
// four surfaces (git smart HTTP, REST v3, GraphQL v4, MCP).
//
// W1's placeholder wires only the boot contract: GET /healthz answers
// {"ok": true} without auth, everything else is a JSON 404. W3 grows
// this package: rest.go (REST v3 dispatcher), gitproto.go (smart HTTP),
// graphql.go and mcp.go live here, all served by Server.
//
// The constructor contract main.go relies on:
//
//	srv := httpapi.NewServer(store) // *httpapi.Server, implements http.Handler
//
// Server holds the store; handlers reach state only through it.
package httpapi

import (
	"encoding/json"
	"net/http"

	"forge/internal/store"
)

// Server is the forge's HTTP server. It implements http.Handler.
type Server struct {
	store *store.Store
	mux   *http.ServeMux
}

// NewServer builds the server over the given store. The returned server
// binds nothing; main.go listens on the ephemeral port and serves it.
func NewServer(s *store.Store) *Server {
	srv := &Server{store: s, mux: http.NewServeMux()}
	srv.routes()
	return srv
}

// Store returns the store this server serves. Handlers in this package
// use srv.store directly; the accessor exists for tests and for main.go.
func (s *Server) Store() *store.Store { return s.store }

// routes registers the placeholder surface. W3 replaces this with the
// full dispatcher: auth middleware, /api/v3/*, /api/graphql, /mcp and
// /{owner}/{repo}/... git smart HTTP. /healthz stays unauthenticated.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	// Everything else: GitHub's JSON 404, until W3's dispatcher lands.
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
	})
}

// ServeHTTP dispatches one request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// writeJSON answers with a JSON body and the GitHub JSON content type.
func writeJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		// A body that cannot marshal is a server bug; answer 500 JSON.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\"message\":\"Internal Server Error\"}\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
