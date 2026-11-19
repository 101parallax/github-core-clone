// Package transport is the forge's raw-TCP HTTP/1.1 server: keep-alive,
// Content-Length framing both ways, chunked request bodies,
// Expect: 100-continue, pipelining tolerated. No net/http on the
// serving path (GHC-RESEARCH.md P0-7, P1-8, P1-12).
//
// Design notes:
//   - Only the headers the forge reads are parsed, dispatched on the
//     header name's first byte. Header names are stored lower-cased in
//     Request.Headers, first value wins.
//   - Per-connection read buffers come from a sync.Pool and are reused
//     across requests on that connection, so pipelined bytes are never
//     lost and no per-request buffer is allocated.
//   - Every response is assembled into one buffer and sent with a
//     single Write, always carrying Content-Length. No chunked
//     responses, no "Connection: close" unless the client asked.
//   - Request bodies are always copied into a fresh exact-size
//     allocation, even when the bytes already sit in the connection
//     buffer. Handlers may therefore keep body bytes (e.g. a file's
//     content decoded from JSON) without aliasing the next request.
//     The copy costs one allocation per request with a body; the read
//     workload (GETs) pays nothing.
//   - The Request struct itself IS reused per connection: handlers must
//     not retain it (or its Headers map) past the call.
//   - No read deadlines: the suite can pause between requests on an
//     open connection. Malformed input is answered 400 and the
//     connection is closed; the server never panics on client input.
//   - Nothing is logged per request.
package transport

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"sync"
)

// Limits. All generous: the conformance suite's largest push is a few
// megabytes, and its longest header line is a short token.
const (
	// maxLineBytes caps one request line, header line, or chunk-size line.
	maxLineBytes = 64 * 1024
	// maxBufferedBytes caps the per-connection read buffer growth. Bodies
	// bypass the buffer (they are read straight into their own
	// allocation), so this only bounds pathological header blocks.
	maxBufferedBytes = 1 << 20
	// maxBodyBytes caps one request body (Content-Length or chunked).
	maxBodyBytes = 64 << 20
	// connBufSize is the pooled per-connection read buffer.
	connBufSize = 32 * 1024
	// maxHeaders caps the header count of one request.
	maxHeaders = 100
)

// errBadRequest marks malformed client input: answer 400, close.
var errBadRequest = errors.New("transport: malformed request")

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
func (r *Request) Header(name string) string {
	if r.Headers == nil {
		return ""
	}
	if v, ok := r.Headers[name]; ok {
		return v
	}
	// Slow path: the caller passed a mixed-case name.
	lower := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	return r.Headers[string(lower)]
}

// QueryParam returns the first value of query key, or "" when absent.
// Keys and values are percent-decoded ('+' decodes to a space, as in
// query strings); a malformed escape falls back to the raw value.
func (r *Request) QueryParam(key string) string {
	q := r.Query
	for len(q) > 0 {
		pair := q
		if i := indexByte(q, '&'); i >= 0 {
			pair, q = q[:i], q[i+1:]
		} else {
			q = ""
		}
		k, v := pair, ""
		if i := indexByte(pair, '='); i >= 0 {
			k, v = pair[:i], pair[i+1:]
		}
		if queryUnescape(k) == key {
			return queryUnescape(v)
		}
	}
	return ""
}

// Response is one HTTP response.
type Response struct {
	Status  int               // e.g. 200
	Headers map[string]string // response headers; Content-Type defaults to
	// "application/json; charset=utf-8" when unset
	// (handlers set it explicitly for git bytes)
	Body []byte // response body (nil = empty body)
}

// Handler handles one request and returns its response.
type Handler interface {
	Handle(req *Request) *Response
}

// Server is the raw-TCP HTTP/1.1 server: keep-alive, Content-Length
// framing both ways, chunked request bodies, Expect: 100-continue,
// pipelining tolerated. No net/http on the serving path.
type Server struct {
	handler Handler

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	closed   bool
}

// NewServer builds a server over handler h.
func NewServer(h Handler) *Server {
	return &Server{handler: h, conns: make(map[net.Conn]struct{})}
}

// Serve accepts connections on l until Close is called. Blocks.
// It returns nil when the server was closed, or the accept error.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.listener = l
	s.mu.Unlock()

	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		if !s.track(conn, true) {
			// Closed between Accept and track: drop the connection.
			_ = conn.Close()
			continue
		}
		go s.serveConn(conn)
	}
}

// Close stops accepting and closes idle connections.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	l := s.listener
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	if l != nil {
		_ = l.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}

// track adds (add=true) or removes a connection from the tracked set.
// It reports false when the server is already closed.
func (s *Server) track(conn net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if add {
		s.conns[conn] = struct{}{}
	} else {
		delete(s.conns, conn)
	}
	return true
}

// bufPool hands out per-connection read buffers.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, connBufSize)
		return &b
	},
}

// serveConn serves one connection until the client goes away, the
// server closes, or a request is malformed.
func (s *Server) serveConn(conn net.Conn) {
	bufp := bufPool.Get().(*[]byte)
	buf := *bufp
	defer func() {
		// Only pool buffers that never grew; a grown buffer keeps its
		// oversized backing array out of the pool.
		if cap(buf) == connBufSize {
			*bufp = buf[:connBufSize]
			bufPool.Put(bufp)
		}
	}()
	defer func() {
		s.track(conn, false)
		_ = conn.Close()
	}()
	// A handler panic must never kill the server: answer 500 and drop
	// this connection. The panic happens before any byte of this
	// request's response is written (responses go out in one Write),
	// so the 500 cannot interleave with a partial response.
	defer func() {
		if r := recover(); r != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n" +
				"Content-Type: application/json; charset=utf-8\r\n" +
				"Content-Length: 35\r\nConnection: close\r\n\r\n" +
				"{\"message\":\"Internal Server Error\"}"))
		}
	}()

	cs := &connState{conn: conn, buf: buf}
	cs.req.Headers = make(map[string]string, 16)
	for {
		closeAfter, err := cs.readRequest()
		if err != nil {
			if errors.Is(err, errBadRequest) {
				_ = cs.writeBadRequest()
			}
			return
		}
		resp := s.handler.Handle(&cs.req)
		if resp == nil {
			resp = internalError
		}
		if err := cs.writeResponse(resp, closeAfter, cs.req.Method == "HEAD"); err != nil {
			return
		}
		if closeAfter {
			return
		}
	}
}

// internalError is the fallback when a handler returns nil.
var internalError = &Response{
	Status: 500,
	Body:   []byte(`{"message":"Internal Server Error"}`),
}

// connState is the per-connection parse/write state.
type connState struct {
	conn net.Conn
	buf  []byte // read buffer; buf[r:w] is unconsumed input
	r, w int
	req  Request

	// Per-request framing, reset by readRequest.
	contentLength  int
	chunked        bool
	expectContinue bool
	closeAfter     bool
	http10         bool
}

// readRequest parses one request into cs.req. It reports whether the
// connection must close after the response. errBadRequest means the
// client sent malformed input (answer 400); any other error means the
// connection is gone (close silently).
func (c *connState) readRequest() (bool, error) {
	c.req.Method = ""
	c.req.Path = ""
	c.req.Query = ""
	c.req.Body = nil
	clear(c.req.Headers)
	c.contentLength = 0
	c.chunked = false
	c.expectContinue = false
	c.closeAfter = false
	c.http10 = false

	line, err := c.readLine()
	if err != nil {
		return false, err
	}
	if err := c.parseRequestLine(line); err != nil {
		return false, err
	}
	for n := 0; ; n++ {
		line, err = c.readLine()
		if err != nil {
			return false, err
		}
		if len(line) == 0 {
			break // end of headers
		}
		if n >= maxHeaders {
			return false, errBadRequest
		}
		if err := c.parseHeader(line); err != nil {
			return false, err
		}
	}

	if c.http10 {
		// HTTP/1.0 defaults to close unless the client asked to keep
		// the connection alive.
		c.closeAfter = c.req.Headers["connection"] != "keep-alive"
	}
	if v := c.req.Headers["connection"]; v != "" && hasToken(v, "close") {
		c.closeAfter = true
	}

	if c.expectContinue {
		// Tell the client to send its body now.
		if _, err := c.conn.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n")); err != nil {
			return false, err
		}
	}
	if c.chunked {
		body, err := c.readChunkedBody()
		if err != nil {
			return false, err
		}
		c.req.Body = body
	} else if c.contentLength > 0 {
		body, err := c.readBody(c.contentLength)
		if err != nil {
			return false, err
		}
		c.req.Body = body
	}
	return c.closeAfter, nil
}

// parseRequestLine splits "METHOD SP TARGET SP HTTP/1.x".
func (c *connState) parseRequestLine(line []byte) error {
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return errBadRequest
	}
	rest := line[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if sp2 <= 0 {
		return errBadRequest
	}
	version := rest[sp2+1:]
	switch string(version) {
	case "HTTP/1.1":
	case "HTTP/1.0":
		c.http10 = true
	default:
		return errBadRequest
	}
	method := line[:sp1]
	for i := 0; i < len(method); i++ {
		if !isTokenByte(method[i]) {
			return errBadRequest
		}
	}
	target := rest[:sp2]
	if len(target) == 0 {
		return errBadRequest
	}
	c.req.Method = string(method)
	return c.parseTarget(target)
}

// parseTarget splits the request target into decoded Path and raw Query.
// Origin-form and absolute-form are both accepted.
func (c *connState) parseTarget(target []byte) error {
	if len(target) == 1 && target[0] == '*' {
		c.req.Path = "*"
		return nil
	}
	if target[0] != '/' {
		// Absolute-form: scheme://authority/path. Strip to the path.
		scheme := bytes.Index(target, []byte("://"))
		if scheme < 0 {
			return errBadRequest
		}
		after := target[scheme+3:]
		slash := bytes.IndexByte(after, '/')
		if slash < 0 {
			target = []byte("/")
		} else {
			target = after[slash:]
		}
	}
	path, query := target, []byte(nil)
	if i := bytes.IndexByte(target, '?'); i >= 0 {
		path, query = target[:i], target[i+1:]
	}
	decoded, err := decodePath(path)
	if err != nil {
		return err
	}
	c.req.Path = decoded
	c.req.Query = string(query)
	return nil
}

// parseHeader handles one "Name: value" line. Only the headers the
// forge reads are kept; the rest are skipped. Dispatch is on the
// header name's first byte (lower-cased), then a full case-insensitive
// compare, so an unknown header costs one byte test.
func (c *connState) parseHeader(line []byte) error {
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return errBadRequest
	}
	name := line[:colon]
	// Header names are tokens; a space inside the name is malformed.
	for i := 0; i < len(name); i++ {
		if !isTokenByte(name[i]) {
			return errBadRequest
		}
	}
	value := trimSpaces(line[colon+1:])

	// First-byte dispatch. The forge reads: authorization, accept,
	// content-length, content-type, connection, expect, git-protocol
	// (v2 smart-HTTP negotiation), host, mcp-session-id (MCP sessions),
	// transfer-encoding, user-agent.
	var key string
	switch name[0] | 0x20 {
	case 'a':
		if headerNameEq(name, "authorization") {
			key = "authorization"
		} else if headerNameEq(name, "accept") {
			key = "accept"
		}
	case 'c':
		if headerNameEq(name, "content-length") {
			key = "content-length"
		} else if headerNameEq(name, "content-type") {
			key = "content-type"
		} else if headerNameEq(name, "connection") {
			key = "connection"
		}
	case 'e':
		if headerNameEq(name, "expect") {
			key = "expect"
		}
	case 'g':
		if headerNameEq(name, "git-protocol") {
			key = "git-protocol"
		}
	case 'h':
		if headerNameEq(name, "host") {
			key = "host"
		}
	case 'm':
		if headerNameEq(name, "mcp-session-id") {
			key = "mcp-session-id"
		}
	case 't':
		if headerNameEq(name, "transfer-encoding") {
			key = "transfer-encoding"
		}
	case 'u':
		if headerNameEq(name, "user-agent") {
			key = "user-agent"
		}
	}
	if key == "" {
		return nil // a header nobody reads: skip it
	}
	if _, ok := c.req.Headers[key]; ok {
		return nil // first value wins
	}
	v := string(value)
	c.req.Headers[key] = v
	switch key {
	case "content-length":
		n, ok := parseContentLength(v)
		if !ok {
			return errBadRequest
		}
		c.contentLength = n
	case "transfer-encoding":
		// Chunked wins over Content-Length (RFC 7230 section 3.3.3).
		if hasToken(v, "chunked") {
			c.chunked = true
		}
	case "expect":
		if headerNameEq(value, "100-continue") {
			c.expectContinue = true
		}
	}
	return nil
}

// readLine returns one line without its terminator (\n, plus a
// trailing \r when present). The slice aliases the connection buffer;
// callers must copy anything they keep.
func (c *connState) readLine() ([]byte, error) {
	for {
		if i := bytes.IndexByte(c.buf[c.r:c.w], '\n'); i >= 0 {
			line := c.buf[c.r : c.r+i]
			c.r += i + 1
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			return line, nil
		}
		if c.w-c.r >= maxLineBytes {
			return nil, errBadRequest
		}
		if err := c.fill(); err != nil {
			return nil, err
		}
	}
}

// fill reads more bytes into the buffer, compacting or growing it
// first when it is full.
func (c *connState) fill() error {
	if c.r == c.w {
		c.r, c.w = 0, 0
	} else if c.w == len(c.buf) {
		copy(c.buf, c.buf[c.r:c.w])
		c.w -= c.r
		c.r = 0
	}
	if c.w == len(c.buf) {
		if len(c.buf) >= maxBufferedBytes {
			return errBadRequest
		}
		ncap := len(c.buf) * 2
		if ncap > maxBufferedBytes {
			ncap = maxBufferedBytes
		}
		nb := make([]byte, ncap)
		copy(nb, c.buf[c.r:c.w])
		c.w -= c.r
		c.r = 0
		c.buf = nb
	}
	n, err := c.conn.Read(c.buf[c.w:])
	if n > 0 {
		c.w += n
		return nil
	}
	return err
}

// readBody reads exactly n body bytes into a fresh allocation. Any
// bytes already buffered are consumed first; the rest are read
// straight from the connection into the new buffer.
func (c *connState) readBody(n int) ([]byte, error) {
	body := make([]byte, n)
	got := copy(body, c.buf[c.r:c.w])
	c.r += got
	for got < n {
		m, err := c.conn.Read(body[got:])
		if err != nil {
			return nil, err
		}
		got += m
	}
	return body, nil
}

// readChunkedBody reads a Transfer-Encoding: chunked body, reassembled
// into one allocation. Trailers after the final chunk are skipped.
func (c *connState) readChunkedBody() ([]byte, error) {
	var out []byte
	for {
		line, err := c.readLine()
		if err != nil {
			return nil, err
		}
		// A chunk-size line may carry extensions after ';'.
		if i := bytes.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		size, ok := parseChunkSize(trimSpaces(line))
		if !ok || len(out)+size > maxBodyBytes {
			return nil, errBadRequest
		}
		if size == 0 {
			// Final chunk: skip trailers up to the empty line.
			for {
				trailer, err := c.readLine()
				if err != nil {
					return nil, err
				}
				if len(trailer) == 0 {
					return out, nil
				}
			}
		}
		chunk, err := c.readBody(size)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		// Each chunk is followed by a CRLF.
		crlf, err := c.readLine()
		if err != nil {
			return nil, err
		}
		if len(crlf) != 0 {
			return nil, errBadRequest
		}
	}
}

// statusLine returns the response status line for a status code.
func statusLine(status int) string {
	switch status {
	case 200:
		return "HTTP/1.1 200 OK\r\n"
	case 201:
		return "HTTP/1.1 201 Created\r\n"
	case 204:
		return "HTTP/1.1 204 No Content\r\n"
	case 400:
		return "HTTP/1.1 400 Bad Request\r\n"
	case 401:
		return "HTTP/1.1 401 Unauthorized\r\n"
	case 403:
		return "HTTP/1.1 403 Forbidden\r\n"
	case 404:
		return "HTTP/1.1 404 Not Found\r\n"
	case 405:
		return "HTTP/1.1 405 Method Not Allowed\r\n"
	case 409:
		return "HTTP/1.1 409 Conflict\r\n"
	case 422:
		return "HTTP/1.1 422 Unprocessable Entity\r\n"
	case 500:
		return "HTTP/1.1 500 Internal Server Error\r\n"
	default:
		if status < 100 || status > 599 {
			status = 500
			return "HTTP/1.1 500 Internal Server Error\r\n"
		}
		return "HTTP/1.1 " + strconv.Itoa(status) + " \r\n"
	}
}

// writeResponse assembles the whole response (status line, headers,
// body) into one buffer and sends it with a single Write. Content-Type
// defaults to JSON when the handler did not set it; Content-Length is
// always set. When head is true (a HEAD request) the headers describe
// the body but the body bytes are withheld.
func (c *connState) writeResponse(resp *Response, closeAfter, head bool) error {
	status := resp.Status
	if status == 0 {
		status = 500
	}
	body := resp.Body

	contentType := ""
	for k, v := range resp.Headers {
		if headerNameEq([]byte(k), "content-type") {
			contentType = v
			break
		}
	}
	if contentType == "" {
		contentType = "application/json; charset=utf-8"
	}

	// Size the buffer once: status line + fixed headers + the
	// handler's headers + the body. A small overestimate is cheaper
	// than a second allocation.
	size := len(body) + 256
	for k, v := range resp.Headers {
		size += len(k) + len(v) + 4
	}
	out := make([]byte, 0, size)
	out = append(out, statusLine(status)...)
	out = append(out, "Content-Type: "...)
	out = append(out, contentType...)
	out = append(out, "\r\nContent-Length: "...)
	out = strconv.AppendInt(out, int64(len(body)), 10)
	out = append(out, "\r\n"...)
	if closeAfter {
		out = append(out, "Connection: close\r\n"...)
	}
	for k, v := range resp.Headers {
		// Content-Type is written above; Content-Length and
		// Connection belong to the transport, not the handler.
		lower0 := byte(0)
		if len(k) > 0 {
			lower0 = k[0] | 0x20
		}
		switch lower0 {
		case 'c':
			if headerNameEq([]byte(k), "content-type") ||
				headerNameEq([]byte(k), "content-length") ||
				headerNameEq([]byte(k), "connection") {
				continue
			}
		}
		out = append(out, k...)
		out = append(out, ": "...)
		out = append(out, v...)
		out = append(out, "\r\n"...)
	}
	out = append(out, "\r\n"...)
	if !head {
		out = append(out, body...)
	}
	_, err := c.conn.Write(out)
	return err
}

// writeBadRequest answers a malformed request with a JSON 400 and
// Connection: close; the caller closes the connection afterwards.
func (c *connState) writeBadRequest() error {
	const body = `{"message":"Bad Request"}`
	out := "HTTP/1.1 400 Bad Request\r\n" +
		"Content-Type: application/json; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_, err := c.conn.Write([]byte(out))
	return err
}

// --- small helpers ---

// indexByte is bytes.IndexByte on a string, avoiding a conversion.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// isTokenByte reports whether b may appear in an HTTP token (a method
// or a header name, RFC 7230 section 3.2.6).
func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// trimSpaces strips leading and trailing SP / HTAB.
func trimSpaces(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// headerNameEq reports whether name equals the lower-case literal,
// comparing ASCII case-insensitively.
func headerNameEq(name []byte, lower string) bool {
	if len(name) != len(lower) {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// hasToken reports whether the comma-separated header value v contains
// the token t (ASCII case-insensitive).
func hasToken(v, t string) bool {
	for len(v) > 0 {
		part := v
		if i := indexByte(v, ','); i >= 0 {
			part, v = v[:i], v[i+1:]
		} else {
			v = ""
		}
		part = string(trimSpaces([]byte(part)))
		if len(part) == len(t) {
			match := true
			for i := 0; i < len(part); i++ {
				c := part[i]
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				if c != t[i] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// parseContentLength parses a decimal Content-Length, rejecting
// anything that is not pure digits or exceeds the body cap.
func parseContentLength(v string) (int, bool) {
	if v == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > maxBodyBytes {
			return 0, false
		}
	}
	return n, true
}

// parseChunkSize parses a hexadecimal chunk size.
func parseChunkSize(v []byte) (int, bool) {
	if len(v) == 0 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(v); i++ {
		var d int
		switch c := v[i]; {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, false
		}
		n = n*16 + d
		if n > maxBodyBytes {
			return 0, false
		}
	}
	return n, true
}

// decodePath percent-decodes a request path. '+' stays literal (it
// only means space in query strings). An invalid escape or a NUL byte
// is an error.
func decodePath(p []byte) (string, error) {
	// Fast path: no escapes at all.
	hasEscape := false
	for i := 0; i < len(p); i++ {
		if p[i] == '%' {
			hasEscape = true
			break
		}
	}
	if !hasEscape {
		return string(p), nil
	}
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c != '%' {
			out = append(out, c)
			continue
		}
		if i+2 >= len(p) {
			return "", errBadRequest
		}
		hi, ok1 := hexVal(p[i+1])
		lo, ok2 := hexVal(p[i+2])
		if !ok1 || !ok2 {
			return "", errBadRequest
		}
		b := hi<<4 | lo
		if b == 0 {
			return "", errBadRequest
		}
		out = append(out, b)
		i += 2
	}
	return string(out), nil
}

// queryUnescape percent-decodes a query key or value, decoding '+'
// to a space. On a malformed escape it returns the raw input.
func queryUnescape(s string) string {
	hasSpecial := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' || s[i] == '+' {
			hasSpecial = true
			break
		}
	}
	if !hasSpecial {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			out = append(out, ' ')
		case c == '%':
			if i+2 >= len(s) {
				return s
			}
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if !ok1 || !ok2 {
				return s
			}
			out = append(out, hi<<4|lo)
			i += 2
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
