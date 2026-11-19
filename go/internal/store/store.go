// Package store is the forge's in-memory state: git objects, repositories,
// issues, pull requests, comments, reviews, labels and users.
//
// Design rules (from GHC-DESIGN.md, the b1 architecture):
//   - No wall clock, no randomness. Every stored timestamp is the store's
//     fixed Now, taken from MAKEFUN_TRIAL_NOW when set (Unix seconds or
//     RFC3339), otherwise the scenario epoch 2025-01-01T00:00:00Z
//     (SCENARIO_EPOCH_SEC in the kit's wire.ts). Wall clock is used only
//     for internal timeouts/retries, never for stored data.
//   - IDs are sequential counters (int64, starting at 1) or content SHA-1s.
//   - List order is insertion order, everywhere. Every entity carries a
//     monotonically increasing Seq so callers can sort deterministically
//     even though all timestamps are equal.
//   - One global sync.RWMutex guards all state. Handlers run concurrently;
//     correctness beats lock granularity here (the store is not the perf
//     bottleneck; pack building is).
//   - Returned pointers are owned by the store. Callers must NOT mutate
//     them directly; use the Update* methods, which run a mutator under
//     the write lock. Git object bytes are immutable once stored.
//   - The store starts empty of repositories: the conformance suite
//     creates everything through the API. Only the 12 scenario users are
//     seeded (viewer adaiversen, id 1000, first).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// ViewerLogin is the login the bearer token names (wire.ts Scenario.viewer).
const ViewerLogin = "adaiversen"

// ViewerID is the viewer's numeric id (wire.ts generateUsers: 1000 + index).
const ViewerID = 1000

// DefaultBranch is the branch every repository is born with.
const DefaultBranch = "main"

// epochSec is SCENARIO_EPOCH_SEC from wire.ts: 2025-01-01T00:00:00Z.
// It is the fixed timestamp used when MAKEFUN_TRIAL_NOW is unset.
const epochSec = 1735689600

// Errors returned by the store. Handlers map these to HTTP statuses:
// ErrNotFound -> 404, ErrExists -> 422, ErrBadLabel -> 422.
var (
	ErrRepoNotFound  = errors.New("store: repository not found")
	ErrRepoExists    = errors.New("store: repository already exists")
	ErrIssueNotFound = errors.New("store: issue not found")
	ErrPRNotFound    = errors.New("store: pull request not found")
	ErrLabelExists   = errors.New("store: label already exists")
	ErrLabelNotFound = errors.New("store: label not found")
	ErrCommentNotFound = errors.New("store: comment not found")
	ErrUserNotFound  = errors.New("store: user not found")
	ErrRefNotFound   = errors.New("store: ref not found")
)

// User is a forge user. The 12 scenario users are seeded at startup;
// no other users are created during a trial (the token names the viewer).
type User struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	Type      string `json:"type"` // "User"
	Seq       int64  `json:"-"`
}

// Ref is one reference: a full refname (refs/heads/main, refs/tags/v1)
// pointing at a commit SHA-1.
type Ref struct {
	Name string `json:"name"`
	SHA  string `json:"sha"`
}

// Repo is a repository. Refs, issues, pull requests, labels and comments
// live in the Store's per-repo state, keyed by RepoKey(Owner, Name);
// this struct holds only the repository's own fields.
type Repo struct {
	ID            int64     `json:"id"`
	Owner         string    `json:"owner"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Private       bool      `json:"private"`
	DefaultBranch string    `json:"default_branch"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Seq           int64     `json:"-"`
}

// FullName returns "owner/name".
func (r *Repo) FullName() string { return r.Owner + "/" + r.Name }

// Key returns the store key for this repository.
func (r *Repo) Key() string { return RepoKey(r.Owner, r.Name) }

// RepoKey is the canonical key for a repository: "owner/name".
func RepoKey(owner, name string) string { return owner + "/" + name }

// RepoOptions carries the fields POST /user/repos accepts.
type RepoOptions struct {
	Description   string
	Private       bool
	DefaultBranch string // "" means DefaultBranch ("main")
}

// Comment is an issue or pull-request comment.
type Comment struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	UserLogin string    `json:"user_login"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Seq       int64     `json:"-"`
}

// Label is a repository label.
type Label struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
	Default     bool   `json:"default"`
	Seq         int64  `json:"-"`
}

// Issue is a repository issue. Number shares one per-repo counter with
// pull requests, as on GitHub: issue #1 and PR #1 can never coexist.
type Issue struct {
	ID         int64      `json:"id"`
	Number     int        `json:"number"`
	Title      string     `json:"title"`
	Body       string     `json:"body"`
	State      string     `json:"state"` // "open" | "closed"
	Labels     []string   `json:"labels"`
	Assignees  []string   `json:"assignees"`
	UserLogin  string     `json:"user_login"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	Comments   []*Comment `json:"-"`
	Seq        int64      `json:"-"`
}

// Review is a pull-request review.
type Review struct {
	ID          int64     `json:"id"`
	Body        string    `json:"body"`
	State       string    `json:"state"` // APPROVED | CHANGES_REQUESTED | COMMENTED | DISMISSED
	UserLogin   string    `json:"user_login"`
	SubmittedAt time.Time `json:"submitted_at"`
	Seq         int64     `json:"-"`
}

// PullRequest is a repository pull request.
type PullRequest struct {
	ID             int64      `json:"id"`
	Number         int        `json:"number"`
	Title          string     `json:"title"`
	Body           string     `json:"body"`
	State          string     `json:"state"` // "open" | "closed"
	HeadRef        string     `json:"head_ref"`
	HeadSHA        string     `json:"head_sha"`
	BaseRef        string     `json:"base_ref"`
	BaseSHA        string     `json:"base_sha"`
	Merged         bool       `json:"merged"`
	Mergeable      bool       `json:"mergeable"`
	MergeCommitSHA string     `json:"merge_commit_sha"`
	MergedAt       *time.Time `json:"merged_at,omitempty"`
	Draft          bool       `json:"draft"`
	UserLogin      string     `json:"user_login"`
	Labels         []string   `json:"labels"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
	Comments       []*Comment `json:"-"`
	Reviews        []*Review  `json:"-"`
	Seq            int64      `json:"-"`
}

// gitObject is one stored git object. Bytes are immutable once stored:
// PutObject copies the caller's slice, GetObject returns the stored
// slice directly (callers must not write into it).
type gitObject struct {
	Type string
	Data []byte
}

// repoState is everything a repository owns besides its own fields.
// It is never exposed; handlers reach it through Store methods.
type repoState struct {
	repo       *Repo
	refs       map[string]string // full refname -> sha
	refOrder   []string          // refnames in creation order
	issues     map[int]*Issue
	issueOrder []int
	prs        map[int]*PullRequest
	prOrder    []int
	labels     map[string]*Label
	labelOrder []string
	nextNumber int // shared issue/PR number counter, starts at 1
}

// Store is the forge's whole state.
type Store struct {
	mu sync.RWMutex

	now time.Time // fixed timestamp for all stored data

	users     map[string]*User
	userOrder []*User

	repos     map[string]*repoState
	repoOrder []string // repo keys in creation order

	objects map[string]*gitObject // sha -> object (content-addressed, shared across repos)

	nextRepoID    int64
	nextEntityID  int64 // issue/PR ids
	nextCommentID int64
	nextLabelID   int64
	nextReviewID  int64
	nextSeq       int64
}

// scenarioUsers are the 12 users wire.ts buildScenario() generates from
// SCENARIO_SEED (computed from the kit; never change them).
var scenarioUsers = []User{
	{ID: 1000, Login: "adaiversen", Name: "ada iversen", Email: "adaiversen@example.invalid"},
	{ID: 1001, Login: "quinnkeller", Name: "quinn keller", Email: "quinnkeller@example.invalid"},
	{ID: 1002, Login: "olgabauer", Name: "olga bauer", Email: "olgabauer@example.invalid"},
	{ID: 1003, Login: "dmitriquist", Name: "dmitri quist", Email: "dmitriquist@example.invalid"},
	{ID: 1004, Login: "adanovak", Name: "ada novak", Email: "adanovak@example.invalid"},
	{ID: 1005, Login: "zanerossi", Name: "zane rossi", Email: "zanerossi@example.invalid"},
	{ID: 1006, Login: "pavelcosta", Name: "pavel costa", Email: "pavelcosta@example.invalid"},
	{ID: 1007, Login: "wrenkeller", Name: "wren keller", Email: "wrenkeller@example.invalid"},
	{ID: 1008, Login: "coraquist", Name: "cora quist", Email: "coraquist@example.invalid"},
	{ID: 1009, Login: "elenaulrich", Name: "elena ulrich", Email: "elenaulrich@example.invalid"},
	{ID: 1010, Login: "tesssato", Name: "tess sato", Email: "tesssato@example.invalid"},
	{ID: 1011, Login: "svenrossi", Name: "sven rossi", Email: "svenrossi@example.invalid"},
}

// trialNow resolves the store's fixed timestamp: MAKEFUN_TRIAL_NOW as
// Unix seconds or RFC3339 when set and parseable, else the scenario epoch.
func trialNow() time.Time {
	raw := os.Getenv("MAKEFUN_TRIAL_NOW")
	if raw != "" {
		if sec, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return time.Unix(sec, 0).UTC()
		}
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Unix(epochSec, 0).UTC()
}

// NewStore builds an empty store seeded with the 12 scenario users.
func NewStore() *Store {
	s := &Store{
		now:           trialNow(),
		users:         make(map[string]*User, len(scenarioUsers)),
		repos:         make(map[string]*repoState),
		objects:       make(map[string]*gitObject),
		nextRepoID:    1,
		nextEntityID:  1,
		nextCommentID: 1,
		nextLabelID:   1,
		nextReviewID:  1,
		nextSeq:       1,
	}
	for _, u := range scenarioUsers {
		user := u
		user.Type = "User"
		user.Seq = s.nextSeq
		s.nextSeq++
		s.users[user.Login] = &user
		s.userOrder = append(s.userOrder, &user)
	}
	return s
}

// Now returns the store's fixed timestamp. Every stored CreatedAt,
// UpdatedAt, MergedAt and ClosedAt is this value.
func (s *Store) Now() time.Time { return s.now }

// NowISO returns the fixed timestamp in RFC3339 (GitHub's timestamp wire
// format, e.g. "2025-01-01T00:00:00Z").
func (s *Store) NowISO() string { return s.now.Format(time.RFC3339) }

// nextSeqLocked returns the next global sequence number. Caller holds mu.
func (s *Store) nextSeqLocked() int64 {
	n := s.nextSeq
	s.nextSeq++
	return n
}

// ---------------------------------------------------------------- repositories

// CreateRepo creates a repository owned by owner. It fails with
// ErrRepoExists when owner/name already exists. The repository starts
// with no refs (unborn): the first contents PUT or push creates the
// default branch.
func (s *Store) CreateRepo(owner, name string, opts RepoOptions) (*Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := RepoKey(owner, name)
	if _, ok := s.repos[key]; ok {
		return nil, ErrRepoExists
	}
	branch := opts.DefaultBranch
	if branch == "" {
		branch = DefaultBranch
	}
	repo := &Repo{
		ID:            s.nextRepoID,
		Owner:         owner,
		Name:          name,
		Description:   opts.Description,
		Private:       opts.Private,
		DefaultBranch: branch,
		CreatedAt:     s.now,
		UpdatedAt:     s.now,
		Seq:           s.nextSeqLocked(),
	}
	s.nextRepoID++
	s.repos[key] = &repoState{
		repo:       repo,
		refs:       make(map[string]string),
		issues:     make(map[int]*Issue),
		prs:        make(map[int]*PullRequest),
		labels:     make(map[string]*Label),
		nextNumber: 1,
	}
	s.repoOrder = append(s.repoOrder, key)
	return repo, nil
}

// GetRepo returns the repository, or ErrRepoNotFound.
func (s *Store) GetRepo(owner, name string) (*Repo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[RepoKey(owner, name)]
	if !ok {
		return nil, ErrRepoNotFound
	}
	return st.repo, nil
}

// HasRepo reports whether owner/name exists.
func (s *Store) HasRepo(owner, name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.repos[RepoKey(owner, name)]
	return ok
}

// ListRepos returns the owner's repositories in creation order.
// An empty owner lists every repository.
func (s *Store) ListRepos(owner string) []*Repo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Repo, 0, len(s.repoOrder))
	for _, key := range s.repoOrder {
		st := s.repos[key]
		if owner == "" || st.repo.Owner == owner {
			out = append(out, st.repo)
		}
	}
	return out
}

// UpdateRepo runs mutate under the write lock and refreshes UpdatedAt.
// The mutator may change Description, Private and DefaultBranch; it must
// not change Owner, Name or ID.
func (s *Store) UpdateRepo(owner, name string, mutate func(*Repo) error) (*Repo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[RepoKey(owner, name)]
	if !ok {
		return nil, ErrRepoNotFound
	}
	if err := mutate(st.repo); err != nil {
		return nil, err
	}
	st.repo.UpdatedAt = s.now
	return st.repo, nil
}

// DeleteRepo removes a repository and everything it owns (refs, issues,
// pull requests, labels, comments). Git objects stay: they are
// content-addressed and shared across repositories.
func (s *Store) DeleteRepo(owner, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := RepoKey(owner, name)
	if _, ok := s.repos[key]; !ok {
		return ErrRepoNotFound
	}
	delete(s.repos, key)
	for i, k := range s.repoOrder {
		if k == key {
			s.repoOrder = append(s.repoOrder[:i], s.repoOrder[i+1:]...)
			break
		}
	}
	return nil
}

// ---------------------------------------------------------------- git objects

// PutObject stores a git object by its SHA-1 hex id. The data slice is
// copied; re-putting the same sha with identical bytes is a no-op, and
// with different bytes overwrites (callers hash content, so a sha always
// names the same bytes in practice).
func (s *Store) PutObject(sha, objType string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	s.objects[sha] = &gitObject{Type: objType, Data: cp}
}

// GetObject returns an object's bytes and type. The returned slice is the
// stored slice: callers must treat it as read-only. ok is false when the
// sha is unknown.
func (s *Store) GetObject(sha string) (data []byte, objType string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	obj, found := s.objects[sha]
	if !found {
		return nil, "", false
	}
	return obj.Data, obj.Type, true
}

// HasObject reports whether sha is stored.
func (s *Store) HasObject(sha string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.objects[sha]
	return ok
}

// ObjectCount returns the number of stored git objects.
func (s *Store) ObjectCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.objects)
}

// ---------------------------------------------------------------- refs

// GetRef returns the sha a ref points at. refname is the full name,
// e.g. "refs/heads/main". ok is false when the repo or ref is unknown.
func (s *Store) GetRef(owner, name, refname string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[RepoKey(owner, name)]
	if !ok {
		return "", false
	}
	sha, ok := st.refs[refname]
	return sha, ok
}

// SetRef points refname at sha, creating the ref when missing.
// It fails with ErrRepoNotFound for an unknown repository.
func (s *Store) SetRef(owner, name, refname, sha string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[RepoKey(owner, name)]
	if !ok {
		return ErrRepoNotFound
	}
	if _, exists := st.refs[refname]; !exists {
		st.refOrder = append(st.refOrder, refname)
	}
	st.refs[refname] = sha
	return nil
}

// DeleteRef removes a ref. It fails with ErrRepoNotFound or
// ErrRefNotFound.
func (s *Store) DeleteRef(owner, name, refname string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[RepoKey(owner, name)]
	if !ok {
		return ErrRepoNotFound
	}
	if _, exists := st.refs[refname]; !exists {
		return ErrRefNotFound
	}
	delete(st.refs, refname)
	for i, n := range st.refOrder {
		if n == refname {
			st.refOrder = append(st.refOrder[:i], st.refOrder[i+1:]...)
			break
		}
	}
	return nil
}

// ListRefs returns every ref of a repository in creation order.
func (s *Store) ListRefs(owner, name string) []Ref {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[RepoKey(owner, name)]
	if !ok {
		return nil
	}
	out := make([]Ref, 0, len(st.refOrder))
	for _, n := range st.refOrder {
		out = append(out, Ref{Name: n, SHA: st.refs[n]})
	}
	return out
}

// ListBranches returns the refs/heads/* refs in creation order, with the
// "refs/heads/" prefix stripped from the name.
func (s *Store) ListBranches(owner, name string) []Ref {
	return s.listRefsWithPrefix(owner, name, "refs/heads/")
}

// ListTags returns the refs/tags/* refs in creation order, with the
// "refs/tags/" prefix stripped from the name.
func (s *Store) ListTags(owner, name string) []Ref {
	return s.listRefsWithPrefix(owner, name, "refs/tags/")
}

func (s *Store) listRefsWithPrefix(owner, name, prefix string) []Ref {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[RepoKey(owner, name)]
	if !ok {
		return nil
	}
	out := make([]Ref, 0)
	for _, n := range st.refOrder {
		if len(n) > len(prefix) && n[:len(prefix)] == prefix {
			out = append(out, Ref{Name: n[len(prefix):], SHA: st.refs[n]})
		}
	}
	return out
}

// DefaultBranchRef returns the full refname of a repository's default
// branch ("refs/heads/<default_branch>").
func (s *Store) DefaultBranchRef(owner, name string) (string, error) {
	repo, err := s.GetRepo(owner, name)
	if err != nil {
		return "", err
	}
	return "refs/heads/" + repo.DefaultBranch, nil
}

// ---------------------------------------------------------------- issues

// CreateIssue creates an open issue in the repository named by repoKey
// ("owner/name"). Labels are stored as given; callers validate them
// against ListLabels first (an unknown label is a 422 at the API layer).
// The issue number comes from the repo's shared issue/PR counter.
func (s *Store) CreateIssue(repoKey, title, body string, labels []string) (*Issue, error) {
	return s.CreateIssueAs(repoKey, ViewerLogin, title, body, labels)
}

// CreateIssueAs is CreateIssue with an explicit author login.
func (s *Store) CreateIssueAs(repoKey, authorLogin, title, body string, labels []string) (*Issue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	issue := &Issue{
		ID:        s.nextEntityID,
		Number:    st.nextNumber,
		Title:     title,
		Body:      body,
		State:     "open",
		Labels:    append([]string(nil), labels...),
		Assignees: []string{},
		UserLogin: authorLogin,
		CreatedAt: s.now,
		UpdatedAt: s.now,
		Seq:       s.nextSeqLocked(),
	}
	s.nextEntityID++
	st.nextNumber++
	st.issues[issue.Number] = issue
	st.issueOrder = append(st.issueOrder, issue.Number)
	return issue, nil
}

// GetIssue returns an issue by number, or false when unknown.
func (s *Store) GetIssue(repoKey string, number int) (*Issue, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, false
	}
	issue, ok := st.issues[number]
	return issue, ok
}

// ListIssues returns a repository's issues in creation order.
func (s *Store) ListIssues(repoKey string) []*Issue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil
	}
	out := make([]*Issue, 0, len(st.issueOrder))
	for _, n := range st.issueOrder {
		out = append(out, st.issues[n])
	}
	return out
}

// UpdateIssue runs mutate under the write lock and refreshes UpdatedAt.
// The mutator may change Title, Body, State, Labels and Assignees; when
// it closes the issue it should set ClosedAt (use s.Now() via the
// passed-in time: callers set issue.ClosedAt = ptr(store.Now())).
func (s *Store) UpdateIssue(repoKey string, number int, mutate func(*Issue) error) (*Issue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	issue, ok := st.issues[number]
	if !ok {
		return nil, ErrIssueNotFound
	}
	if err := mutate(issue); err != nil {
		return nil, err
	}
	issue.UpdatedAt = s.now
	return issue, nil
}

// ---------------------------------------------------------------- pull requests

// PROptions carries the fields POST /pulls accepts.
type PROptions struct {
	Title   string
	Body    string
	HeadRef string // branch name, e.g. "feature/x"
	HeadSHA string // head branch tip at creation
	BaseRef string // branch name, e.g. "main"
	BaseSHA string // base branch tip at creation
	Author  string // "" means the viewer
	Draft   bool
}

// CreatePR creates an open pull request. The number comes from the repo's
// shared issue/PR counter. Mergeable starts true; the merge path recomputes
// it from the trees before merging.
func (s *Store) CreatePR(repoKey string, opts PROptions) (*PullRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	author := opts.Author
	if author == "" {
		author = ViewerLogin
	}
	pr := &PullRequest{
		ID:        s.nextEntityID,
		Number:    st.nextNumber,
		Title:     opts.Title,
		Body:      opts.Body,
		State:     "open",
		HeadRef:   opts.HeadRef,
		HeadSHA:   opts.HeadSHA,
		BaseRef:   opts.BaseRef,
		BaseSHA:   opts.BaseSHA,
		Merged:    false,
		Mergeable: true,
		Draft:     opts.Draft,
		UserLogin: author,
		Labels:    []string{},
		CreatedAt: s.now,
		UpdatedAt: s.now,
		Seq:       s.nextSeqLocked(),
	}
	s.nextEntityID++
	st.nextNumber++
	st.prs[pr.Number] = pr
	st.prOrder = append(st.prOrder, pr.Number)
	return pr, nil
}

// GetPR returns a pull request by number, or false when unknown.
func (s *Store) GetPR(repoKey string, number int) (*PullRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, false
	}
	pr, ok := st.prs[number]
	return pr, ok
}

// ListPRs returns a repository's pull requests in creation order.
func (s *Store) ListPRs(repoKey string) []*PullRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil
	}
	out := make([]*PullRequest, 0, len(st.prOrder))
	for _, n := range st.prOrder {
		out = append(out, st.prs[n])
	}
	return out
}

// UpdatePR runs mutate under the write lock and refreshes UpdatedAt.
// The merge path uses this to set State="closed", Merged=true,
// MergeCommitSHA and MergedAt together.
func (s *Store) UpdatePR(repoKey string, number int, mutate func(*PullRequest) error) (*PullRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	pr, ok := st.prs[number]
	if !ok {
		return nil, ErrPRNotFound
	}
	if err := mutate(pr); err != nil {
		return nil, err
	}
	pr.UpdatedAt = s.now
	return pr, nil
}

// ---------------------------------------------------------------- comments

// AddIssueComment appends a comment to an issue.
func (s *Store) AddIssueComment(repoKey string, number int, body, authorLogin string) (*Comment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	issue, ok := st.issues[number]
	if !ok {
		return nil, ErrIssueNotFound
	}
	comment := s.newCommentLocked(body, authorLogin)
	issue.Comments = append(issue.Comments, comment)
	return comment, nil
}

// AddPRComment appends a comment to a pull request.
func (s *Store) AddPRComment(repoKey string, number int, body, authorLogin string) (*Comment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	pr, ok := st.prs[number]
	if !ok {
		return nil, ErrPRNotFound
	}
	comment := s.newCommentLocked(body, authorLogin)
	pr.Comments = append(pr.Comments, comment)
	return comment, nil
}

func (s *Store) newCommentLocked(body, authorLogin string) *Comment {
	comment := &Comment{
		ID:        s.nextCommentID,
		Body:      body,
		UserLogin: authorLogin,
		CreatedAt: s.now,
		UpdatedAt: s.now,
		Seq:       s.nextSeqLocked(),
	}
	s.nextCommentID++
	return comment
}

// ListIssueComments returns an issue's comments in creation order.
func (s *Store) ListIssueComments(repoKey string, number int) ([]*Comment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	issue, ok := st.issues[number]
	if !ok {
		return nil, ErrIssueNotFound
	}
	out := make([]*Comment, len(issue.Comments))
	copy(out, issue.Comments)
	return out, nil
}

// ListPRComments returns a pull request's comments in creation order.
func (s *Store) ListPRComments(repoKey string, number int) ([]*Comment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	pr, ok := st.prs[number]
	if !ok {
		return nil, ErrPRNotFound
	}
	out := make([]*Comment, len(pr.Comments))
	copy(out, pr.Comments)
	return out, nil
}

// UpdateIssueComment rewrites one issue comment's body.
func (s *Store) UpdateIssueComment(repoKey string, number int, commentID int64, body string) (*Comment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	issue, ok := st.issues[number]
	if !ok {
		return nil, ErrIssueNotFound
	}
	for _, c := range issue.Comments {
		if c.ID == commentID {
			c.Body = body
			c.UpdatedAt = s.now
			return c, nil
		}
	}
	return nil, ErrCommentNotFound
}

// DeleteIssueComment removes one issue comment.
func (s *Store) DeleteIssueComment(repoKey string, number int, commentID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return ErrRepoNotFound
	}
	issue, ok := st.issues[number]
	if !ok {
		return ErrIssueNotFound
	}
	for i, c := range issue.Comments {
		if c.ID == commentID {
			issue.Comments = append(issue.Comments[:i], issue.Comments[i+1:]...)
			return nil
		}
	}
	return ErrCommentNotFound
}

// ---------------------------------------------------------------- reviews

// AddReview appends a review to a pull request.
func (s *Store) AddReview(repoKey string, number int, body, state, authorLogin string) (*Review, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	pr, ok := st.prs[number]
	if !ok {
		return nil, ErrPRNotFound
	}
	review := &Review{
		ID:          s.nextReviewID,
		Body:        body,
		State:       state,
		UserLogin:   authorLogin,
		SubmittedAt: s.now,
		Seq:         s.nextSeqLocked(),
	}
	s.nextReviewID++
	pr.Reviews = append(pr.Reviews, review)
	return review, nil
}

// ListReviews returns a pull request's reviews in creation order.
func (s *Store) ListReviews(repoKey string, number int) ([]*Review, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	pr, ok := st.prs[number]
	if !ok {
		return nil, ErrPRNotFound
	}
	out := make([]*Review, len(pr.Reviews))
	copy(out, pr.Reviews)
	return out, nil
}

// ---------------------------------------------------------------- labels

// CreateLabel creates a label. It fails with ErrLabelExists when the
// name is already taken in this repository.
func (s *Store) CreateLabel(repoKey, name, color, description string) (*Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	if _, exists := st.labels[name]; exists {
		return nil, ErrLabelExists
	}
	label := &Label{
		ID:          s.nextLabelID,
		Name:        name,
		Color:       color,
		Description: description,
		Seq:         s.nextSeqLocked(),
	}
	s.nextLabelID++
	st.labels[name] = label
	st.labelOrder = append(st.labelOrder, name)
	return label, nil
}

// GetLabel returns a label by name, or false when unknown.
func (s *Store) GetLabel(repoKey, name string) (*Label, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, false
	}
	label, ok := st.labels[name]
	return label, ok
}

// HasLabel reports whether a label name exists in the repository.
func (s *Store) HasLabel(repoKey, name string) bool {
	_, ok := s.GetLabel(repoKey, name)
	return ok
}

// ListLabels returns a repository's labels in creation order.
func (s *Store) ListLabels(repoKey string) []*Label {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil
	}
	out := make([]*Label, 0, len(st.labelOrder))
	for _, n := range st.labelOrder {
		out = append(out, st.labels[n])
	}
	return out
}

// UpdateLabel renames and/or recolors a label. An empty newName keeps the
// old name; a rename to an existing name fails with ErrLabelExists.
func (s *Store) UpdateLabel(repoKey, name, newName, color, description string) (*Label, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return nil, ErrRepoNotFound
	}
	label, ok := st.labels[name]
	if !ok {
		return nil, ErrLabelNotFound
	}
	if newName != "" && newName != name {
		if _, exists := st.labels[newName]; exists {
			return nil, ErrLabelExists
		}
		delete(st.labels, name)
		label.Name = newName
		st.labels[newName] = label
		for i, n := range st.labelOrder {
			if n == name {
				st.labelOrder[i] = newName
				break
			}
		}
	}
	if color != "" {
		label.Color = color
	}
	label.Description = description
	return label, nil
}

// DeleteLabel removes a label from the repository.
func (s *Store) DeleteLabel(repoKey, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.repos[repoKey]
	if !ok {
		return ErrRepoNotFound
	}
	if _, exists := st.labels[name]; !exists {
		return ErrLabelNotFound
	}
	delete(st.labels, name)
	for i, n := range st.labelOrder {
		if n == name {
			st.labelOrder = append(st.labelOrder[:i], st.labelOrder[i+1:]...)
			break
		}
	}
	return nil
}

// ---------------------------------------------------------------- users

// GetUser returns a user by login, or false when unknown.
func (s *Store) GetUser(login string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[login]
	return user, ok
}

// Viewer returns the token owner (adaiversen). It always exists.
func (s *Store) Viewer() *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[ViewerLogin]
}

// ListUsers returns the seeded users in id order.
func (s *Store) ListUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, len(s.userOrder))
	copy(out, s.userOrder)
	return out
}

// ---------------------------------------------------------------- export

// exportObject is one git object in the export: identity and size only,
// never the bytes (the export stays small and still proves the set).
type exportObject struct {
	SHA  string `json:"sha"`
	Type string `json:"type"`
	Size int    `json:"size"`
}

// exportRepo is one repository in the export.
type exportRepo struct {
	Repo   *Repo          `json:"repo"`
	Refs   []Ref          `json:"refs"`
	Issues []*Issue       `json:"issues"`
	PRs    []*PullRequest `json:"pull_requests"`
	Labels []*Label       `json:"labels"`
}

// exportSnapshot is the whole state in a deterministic shape: repos
// sorted by owner/name, refs sorted by name, objects sorted by sha.
// encoding/json sorts map keys, so the bytes are stable across runs for
// the same sequence of operations.
type exportSnapshot struct {
	Version int           `json:"version"`
	Now     string        `json:"now"`
	Users   []*User       `json:"users"`
	Repos   []exportRepo  `json:"repos"`
	Objects []exportObject `json:"objects"`
}

// Export returns the full state as deterministic JSON: the same sequence
// of operations always produces byte-identical output. It is the local
// debugging snapshot; the grader's own export (state.json) is written by
// the env, not by the entry.
func (s *Store) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*User, len(s.userOrder))
	copy(users, s.userOrder)

	keys := make([]string, 0, len(s.repos))
	for k := range s.repos {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	repos := make([]exportRepo, 0, len(keys))
	for _, k := range keys {
		st := s.repos[k]
		refs := make([]Ref, 0, len(st.refs))
		for name, sha := range st.refs {
			refs = append(refs, Ref{Name: name, SHA: sha})
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
		issues := make([]*Issue, 0, len(st.issueOrder))
		for _, n := range st.issueOrder {
			issues = append(issues, st.issues[n])
		}
		prs := make([]*PullRequest, 0, len(st.prOrder))
		for _, n := range st.prOrder {
			prs = append(prs, st.prs[n])
		}
		labels := make([]*Label, 0, len(st.labelOrder))
		for _, n := range st.labelOrder {
			labels = append(labels, st.labels[n])
		}
		repos = append(repos, exportRepo{Repo: st.repo, Refs: refs, Issues: issues, PRs: prs, Labels: labels})
	}

	objects := make([]exportObject, 0, len(s.objects))
	for sha, obj := range s.objects {
		objects = append(objects, exportObject{SHA: sha, Type: obj.Type, Size: len(obj.Data)})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].SHA < objects[j].SHA })

	snap := exportSnapshot{
		Version: 1,
		Now:     s.now.Format(time.RFC3339),
		Users:   users,
		Repos:   repos,
		Objects: objects,
	}
	return json.Marshal(snap)
}

// Stats returns a one-line summary for logs: repos, objects, issues, PRs.
func (s *Store) Stats() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	issues, prs := 0, 0
	for _, st := range s.repos {
		issues += len(st.issues)
		prs += len(st.prs)
	}
	return fmt.Sprintf("repos=%d objects=%d issues=%d prs=%d", len(s.repos), len(s.objects), issues, prs)
}
