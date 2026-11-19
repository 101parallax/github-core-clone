// Command forge is the github-core-clone-01 entry: a GitHub-compatible
// git forge in a single Go binary, zero dependencies.
//
// Boot lifecycle (wire.ts / starter main.ts — the harness's contract,
// not the contest's):
//  1. MAKEFUN_ENV_URL names the env's origin. Without it there is nothing
//     to talk to, so the program exits 1 at once.
//  2. Bind an ephemeral port (127.0.0.1:0). NEVER bind 8080: the env owns it.
//  3. POST $MAKEFUN_ENV_URL/register {"port": N} with retry and exponential
//     backoff (250ms -> 2s cap, 30s request timeout). 200 or 409 is
//     success; 400/405 is a contract error and ends the program.
//  4. GET $MAKEFUN_ENV_URL/done until the body is {"done": true}. The env
//     answers at once, so this is a poll, never a long-held request.
//     A failed or slow poll is retried with backoff; the process never
//     exits before the env says done.
//  5. Close the server gracefully and exit 0.
//
// GET /healthz answers {"ok": true} without a token (the env's boot
// check calls it twice). Every other surface requires
// Authorization: Bearer <MAKEFUN_SHOP_TOKEN> (enforced in httpapi).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"forge/internal/httpapi"
	"forge/internal/store"
)

// requestTimeout bounds one register or done request.
const requestTimeout = 30 * time.Second

// retryInitialMs / retryMaxMs bound the exponential backoff between
// retries (250ms, doubling, capped at 2s), as in the starter.
const (
	retryInitialMs = 250
	retryMaxMs     = 2000
)

// retryDelay is the wait after `attempt` failed requests: exponential
// from retryInitialMs, capped at retryMaxMs.
func retryDelay(attempt int) time.Duration {
	if attempt > 8 {
		attempt = 8
	}
	ms := retryInitialMs << attempt
	if ms > retryMaxMs {
		ms = retryMaxMs
	}
	return time.Duration(ms) * time.Millisecond
}

// registerError is fatal: the env answered 400 or 405, a contract error
// that retrying cannot fix.
type registerError struct{ status int }

func (e *registerError) Error() string {
	return fmt.Sprintf("register answered HTTP %d", e.status)
}

// register POSTs the bound port until the env accepts it. 200 is the
// normal answer; 409 means a first register already won, which is not
// this process's to fix. A network error or another status is retried,
// since the env may still be starting.
func register(envURL string, port int) error {
	client := &http.Client{Timeout: requestTimeout}
	body, err := json.Marshal(map[string]int{"port": port})
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, envURL+"/register", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK, http.StatusConflict:
				return nil
			case http.StatusBadRequest, http.StatusMethodNotAllowed:
				return &registerError{status: resp.StatusCode}
			}
		}
		time.Sleep(retryDelay(attempt))
	}
}

// pollDoneOnce performs one GET /done poll. It reports whether the env
// answered {"done": true}; any failure means "not done yet".
func pollDoneOnce(client *http.Client, envURL string) bool {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, envURL+"/done", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var decoded struct {
		Done bool `json:"done"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return false
	}
	return decoded.Done
}

// waitForDone polls GET /done until it answers {"done": true}.
// It never returns before that.
func waitForDone(envURL string) {
	client := &http.Client{Timeout: requestTimeout}
	for attempt := 0; ; attempt++ {
		if pollDoneOnce(client, envURL) {
			return
		}
		time.Sleep(retryDelay(attempt))
	}
}

func run() error {
	envURL := strings.TrimRight(os.Getenv("MAKEFUN_ENV_URL"), "/")
	if envURL == "" {
		return errors.New("MAKEFUN_ENV_URL is not set: there is no env to register with")
	}

	// The store and the server. The server binds nothing until Serve runs.
	st := store.NewStore()
	srv := httpapi.NewServer(st)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on an ephemeral port: %w", err)
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return errors.New("the listener did not bind a TCP port")
	}
	port := addr.Port
	fmt.Fprintf(os.Stdout, "[entry] listening on port %d\n", port)

	httpServer := &http.Server{Handler: srv}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpServer.Serve(listener)
	}()

	// Register the bound port, then wait for the env to say done.
	if err := register(envURL, port); err != nil {
		_ = httpServer.Close()
		return err
	}
	fmt.Fprintln(os.Stdout, "[entry] registered; waiting for the env to say done")

	waitForDone(envURL)

	// The suite is over: shut the server down and exit 0.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shut down the server: %w", err)
	}
	<-serveErr // Serve returns ErrServerClosed after Shutdown; ignore it.
	fmt.Fprintln(os.Stdout, "[entry] done")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "[entry] %v\n", err)
		os.Exit(1)
	}
}
