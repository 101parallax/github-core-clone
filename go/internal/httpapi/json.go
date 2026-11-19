// Hand-rolled JSON encoding for the REST v3 hot response types.
//
// GHC-RESEARCH.md P0-5: encoding/json costs ~445 ns/op and 2 allocations
// per marshal; these encoders run ~8x faster at 0 allocations on the hot
// path (the caller supplies a pre-sized destination buffer, P0-9).
//
// Every encoder MUST byte-match encoding/json output for the same value,
// including HTML escaping (< -> \u003c, > -> \u003e, & -> \u0026),
// \u2028/\u2029 escaping, and \ufffd for invalid UTF-8 bytes. The
// byte-compare test (kept outside the repo) verifies this against
// json.Marshal on an adversarial corpus.
//
// Timestamps: every stored timestamp in the forge is the store's fixed
// Now, so encoders take the pre-formatted RFC3339 string once
// (restEncodeCtx.now) instead of formatting time.Time per field.
//
// All authors in the system are the token viewer (every surface creates
// as the viewer), so user objects resolve the viewer id from the store
// constants without a lookup; any other login encodes with id 0.
package httpapi

import (
	"strconv"
	"unicode/utf8"

	"forge/internal/store"
)

// restEncodeCtx carries the per-request values the encoders need: the
// pre-formatted fixed timestamp and the repo's label lookup table
// (issue/PR labels carry their colour, which lives on the label).
// Callers build it once per request from a single ListLabels call;
// labels may be nil when the entity has no labels.
type restEncodeCtx struct {
	now    string
	labels map[string]*store.Label
}

// jsonHexDigits is the lowercase hex alphabet for \u00XX escapes.
const jsonHexDigits = "0123456789abcdef"

// appendJSONString appends s as a JSON string literal, byte-identical to
// encoding/json with HTML escaping enabled (the encoding/json default):
// '"' and '\' are backslash-escaped, \n \r \t use short escapes, other
// control bytes become \u00XX, '<' '>' '&' become \u003c \u003e \u0026,
// U+2028/U+2029 become \u2028 \u2029, invalid UTF-8 bytes become \ufffd,
// and everything else (including DEL and valid multibyte runes) passes
// through unchanged.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < utf8.RuneSelf {
			// Fast path: printable ASCII that needs no escaping.
			if c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&' {
				continue
			}
			if start < i {
				dst = append(dst, s[start:i]...)
			}
			switch c {
			case '"', '\\':
				dst = append(dst, '\\', c)
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			case '<':
				dst = append(dst, '\\', 'u', '0', '0', '3', 'c')
			case '>':
				dst = append(dst, '\\', 'u', '0', '0', '3', 'e')
			case '&':
				dst = append(dst, '\\', 'u', '0', '0', '2', '6')
			default: // any other control byte
				dst = append(dst, '\\', 'u', '0', '0', jsonHexDigits[c>>4], jsonHexDigits[c&0x0f])
			}
			start = i + 1
			continue
		}
		// Multibyte rune: only U+2028/U+2029 and invalid UTF-8 escape.
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			if start < i {
				dst = append(dst, s[start:i]...)
			}
			dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
			start = i + 1
		case r == '\u2028' || r == '\u2029':
			if start < i {
				dst = append(dst, s[start:i]...)
			}
			dst = append(dst, '\\', 'u', '2', '0', '2', '8'+byte(r-'\u2028'))
			start = i + size
		}
		i += size - 1
	}
	if start < len(s) {
		dst = append(dst, s[start:]...)
	}
	return append(dst, '"')
}

// appendJSONBool appends a JSON boolean literal.
func appendJSONBool(dst []byte, b bool) []byte {
	if b {
		return append(dst, "true"...)
	}
	return append(dst, "false"...)
}

// appendJSONInt appends a JSON integer.
func appendJSONInt(dst []byte, n int64) []byte {
	return strconv.AppendInt(dst, n, 10)
}

// appendUserRefJSON appends the compact user object GitHub nests inside
// issues, PRs and comments: {"login":...,"id":...,"avatar_url":"","type":"User"}.
func appendUserRefJSON(dst []byte, login string) []byte {
	dst = append(dst, `{"login":`...)
	dst = appendJSONString(dst, login)
	dst = append(dst, `,"id":`...)
	if login == store.ViewerLogin {
		dst = appendJSONInt(dst, store.ViewerID)
	} else {
		dst = append(dst, '0')
	}
	dst = append(dst, `,"avatar_url":"","type":"User"}`...)
	return dst
}

// appendTimeOrNull appends a quoted RFC3339 timestamp, or null when isNil.
// Every real timestamp equals ctx.now (the store's fixed Now), so the
// value is never formatted here.
func appendTimeOrNull(dst []byte, now string, isNil bool) []byte {
	if isNil {
		return append(dst, "null"...)
	}
	dst = append(dst, '"')
	dst = append(dst, now...)
	return append(dst, '"')
}

// appendStringListJSON appends a JSON array of strings ([] for nil/empty).
func appendStringListJSON(dst []byte, items []string) []byte {
	dst = append(dst, '[')
	for i, item := range items {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, item)
	}
	return append(dst, ']')
}

// appendIssueLabelsJSON appends the labels array of an issue or PR:
// full label objects looked up by name in ctx.labels. A name with no
// label (deleted after the issue was created) encodes with empty
// colour/description and id 0 rather than disappearing.
func appendIssueLabelsJSON(dst []byte, names []string, ctx *restEncodeCtx) []byte {
	dst = append(dst, '[')
	for i, name := range names {
		if i > 0 {
			dst = append(dst, ',')
		}
		if label, ok := ctx.labels[name]; ok {
			dst = encodeLabel(dst, label)
			continue
		}
		dst = append(dst, `{"id":0,"name":`...)
		dst = appendJSONString(dst, name)
		dst = append(dst, `,"color":"","description":"","default":false}`...)
	}
	return append(dst, ']')
}

// encodeIssue appends the GitHub issue object. Field order mirrors the
// GitHub wire shape; the byte-compare test pins it.
func encodeIssue(dst []byte, issue *store.Issue, ctx *restEncodeCtx) []byte {
	dst = append(dst, `{"id":`...)
	dst = appendJSONInt(dst, issue.ID)
	dst = append(dst, `,"number":`...)
	dst = appendJSONInt(dst, int64(issue.Number))
	dst = append(dst, `,"title":`...)
	dst = appendJSONString(dst, issue.Title)
	dst = append(dst, `,"body":`...)
	dst = appendJSONString(dst, issue.Body)
	dst = append(dst, `,"state":`...)
	dst = appendJSONString(dst, issue.State)
	dst = append(dst, `,"labels":`...)
	dst = appendIssueLabelsJSON(dst, issue.Labels, ctx)
	dst = append(dst, `,"assignees":`...)
	dst = appendStringListJSON(dst, issue.Assignees)
	dst = append(dst, `,"user":`...)
	dst = appendUserRefJSON(dst, issue.UserLogin)
	dst = append(dst, `,"created_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, `","updated_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, `","closed_at":`...)
	dst = appendTimeOrNull(dst, ctx.now, issue.ClosedAt == nil)
	dst = append(dst, '}')
	return dst
}

// encodeIssueList appends a JSON array of issues.
func encodeIssueList(dst []byte, issues []*store.Issue, ctx *restEncodeCtx) []byte {
	dst = append(dst, '[')
	for i, issue := range issues {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = encodeIssue(dst, issue, ctx)
	}
	return append(dst, ']')
}

// encodeRepo appends the GitHub repository object.
func encodeRepo(dst []byte, repo *store.Repo, ctx *restEncodeCtx) []byte {
	dst = append(dst, `{"id":`...)
	dst = appendJSONInt(dst, repo.ID)
	dst = append(dst, `,"name":`...)
	dst = appendJSONString(dst, repo.Name)
	dst = append(dst, `,"full_name":`...)
	dst = appendJSONString(dst, repo.FullName())
	dst = append(dst, `,"owner":`...)
	dst = appendUserRefJSON(dst, repo.Owner)
	dst = append(dst, `,"private":`...)
	dst = appendJSONBool(dst, repo.Private)
	dst = append(dst, `,"description":`...)
	dst = appendJSONString(dst, repo.Description)
	dst = append(dst, `,"default_branch":`...)
	dst = appendJSONString(dst, repo.DefaultBranch)
	dst = append(dst, `,"created_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, `","updated_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, '"', '}')
	return dst
}

// encodeRepoList appends a JSON array of repositories.
func encodeRepoList(dst []byte, repos []*store.Repo, ctx *restEncodeCtx) []byte {
	dst = append(dst, '[')
	for i, repo := range repos {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = encodeRepo(dst, repo, ctx)
	}
	return append(dst, ']')
}

// encodePR appends the GitHub pull-request object.
func encodePR(dst []byte, pr *store.PullRequest, ctx *restEncodeCtx) []byte {
	dst = append(dst, `{"id":`...)
	dst = appendJSONInt(dst, pr.ID)
	dst = append(dst, `,"number":`...)
	dst = appendJSONInt(dst, int64(pr.Number))
	dst = append(dst, `,"title":`...)
	dst = appendJSONString(dst, pr.Title)
	dst = append(dst, `,"body":`...)
	dst = appendJSONString(dst, pr.Body)
	dst = append(dst, `,"state":`...)
	dst = appendJSONString(dst, pr.State)
	dst = append(dst, `,"head":{"ref":`...)
	dst = appendJSONString(dst, pr.HeadRef)
	dst = append(dst, `,"sha":`...)
	dst = appendJSONString(dst, pr.HeadSHA)
	dst = append(dst, `},"base":{"ref":`...)
	dst = appendJSONString(dst, pr.BaseRef)
	dst = append(dst, `,"sha":`...)
	dst = appendJSONString(dst, pr.BaseSHA)
	dst = append(dst, `},"merged":`...)
	dst = appendJSONBool(dst, pr.Merged)
	dst = append(dst, `,"mergeable":`...)
	dst = appendJSONBool(dst, pr.Mergeable)
	dst = append(dst, `,"merge_commit_sha":`...)
	if pr.MergeCommitSHA == "" {
		dst = append(dst, "null"...)
	} else {
		dst = appendJSONString(dst, pr.MergeCommitSHA)
	}
	dst = append(dst, `,"merged_at":`...)
	dst = appendTimeOrNull(dst, ctx.now, pr.MergedAt == nil)
	dst = append(dst, `,"draft":`...)
	dst = appendJSONBool(dst, pr.Draft)
	dst = append(dst, `,"user":`...)
	dst = appendUserRefJSON(dst, pr.UserLogin)
	dst = append(dst, `,"labels":`...)
	dst = appendIssueLabelsJSON(dst, pr.Labels, ctx)
	dst = append(dst, `,"created_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, `","updated_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, `","closed_at":`...)
	dst = appendTimeOrNull(dst, ctx.now, pr.ClosedAt == nil)
	dst = append(dst, '}')
	return dst
}

// encodePRList appends a JSON array of pull requests.
func encodePRList(dst []byte, prs []*store.PullRequest, ctx *restEncodeCtx) []byte {
	dst = append(dst, '[')
	for i, pr := range prs {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = encodePR(dst, pr, ctx)
	}
	return append(dst, ']')
}

// encodeComment appends the GitHub comment object (issue and PR comments
// share the shape).
func encodeComment(dst []byte, comment *store.Comment, ctx *restEncodeCtx) []byte {
	dst = append(dst, `{"id":`...)
	dst = appendJSONInt(dst, comment.ID)
	dst = append(dst, `,"body":`...)
	dst = appendJSONString(dst, comment.Body)
	dst = append(dst, `,"user":`...)
	dst = appendUserRefJSON(dst, comment.UserLogin)
	dst = append(dst, `,"created_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, `","updated_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, '"', '}')
	return dst
}

// encodeCommentList appends a JSON array of comments.
func encodeCommentList(dst []byte, comments []*store.Comment, ctx *restEncodeCtx) []byte {
	dst = append(dst, '[')
	for i, comment := range comments {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = encodeComment(dst, comment, ctx)
	}
	return append(dst, ']')
}

// encodeReview appends a pull-request review object.
func encodeReview(dst []byte, review *store.Review, ctx *restEncodeCtx) []byte {
	dst = append(dst, `{"id":`...)
	dst = appendJSONInt(dst, review.ID)
	dst = append(dst, `,"body":`...)
	dst = appendJSONString(dst, review.Body)
	dst = append(dst, `,"state":`...)
	dst = appendJSONString(dst, review.State)
	dst = append(dst, `,"user":`...)
	dst = appendUserRefJSON(dst, review.UserLogin)
	dst = append(dst, `,"submitted_at":"`...)
	dst = append(dst, ctx.now...)
	dst = append(dst, '"', '}')
	return dst
}

// encodeReviewList appends a JSON array of reviews.
func encodeReviewList(dst []byte, reviews []*store.Review, ctx *restEncodeCtx) []byte {
	dst = append(dst, '[')
	for i, review := range reviews {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = encodeReview(dst, review, ctx)
	}
	return append(dst, ']')
}

// encodeUser appends the full GitHub user object (GET /api/v3/user).
func encodeUser(dst []byte, user *store.User) []byte {
	dst = append(dst, `{"id":`...)
	dst = appendJSONInt(dst, user.ID)
	dst = append(dst, `,"login":`...)
	dst = appendJSONString(dst, user.Login)
	dst = append(dst, `,"name":`...)
	dst = appendJSONString(dst, user.Name)
	dst = append(dst, `,"email":`...)
	dst = appendJSONString(dst, user.Email)
	dst = append(dst, `,"avatar_url":`...)
	dst = appendJSONString(dst, user.AvatarURL)
	dst = append(dst, `,"type":`...)
	dst = appendJSONString(dst, user.Type)
	dst = append(dst, '}')
	return dst
}

// encodeLabel appends a GitHub label object.
func encodeLabel(dst []byte, label *store.Label) []byte {
	dst = append(dst, `{"id":`...)
	dst = appendJSONInt(dst, label.ID)
	dst = append(dst, `,"name":`...)
	dst = appendJSONString(dst, label.Name)
	dst = append(dst, `,"color":`...)
	dst = appendJSONString(dst, label.Color)
	dst = append(dst, `,"description":`...)
	dst = appendJSONString(dst, label.Description)
	dst = append(dst, `,"default":`...)
	dst = appendJSONBool(dst, label.Default)
	dst = append(dst, '}')
	return dst
}

// encodeLabelList appends a JSON array of labels.
func encodeLabelList(dst []byte, labels []*store.Label) []byte {
	dst = append(dst, '[')
	for i, label := range labels {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = encodeLabel(dst, label)
	}
	return append(dst, ']')
}

// encodeRef appends the Git Data API ref object: {"ref":...,"object":{"sha":...}}.
func encodeRef(dst []byte, ref, sha string) []byte {
	dst = append(dst, `{"ref":`...)
	dst = appendJSONString(dst, ref)
	dst = append(dst, `,"object":{"sha":`...)
	dst = appendJSONString(dst, sha)
	dst = append(dst, '}', '}')
	return dst
}

// encodeBranch appends a branch list item: {"name":...,"commit":{"sha":...}}.
func encodeBranch(dst []byte, name, sha string) []byte {
	dst = append(dst, `{"name":`...)
	dst = appendJSONString(dst, name)
	dst = append(dst, `,"commit":{"sha":`...)
	dst = appendJSONString(dst, sha)
	dst = append(dst, '}', '}')
	return dst
}

// encodeBranchList appends a JSON array of branches.
func encodeBranchList(dst []byte, branches []store.Ref) []byte {
	dst = append(dst, '[')
	for i, branch := range branches {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = encodeBranch(dst, branch.Name, branch.SHA)
	}
	return append(dst, ']')
}

// encodeCommit appends a commit list item: {"sha":...,"commit":{"message":...}}.
func encodeCommit(dst []byte, sha, message string) []byte {
	dst = append(dst, `{"sha":`...)
	dst = appendJSONString(dst, sha)
	dst = append(dst, `,"commit":{"message":`...)
	dst = appendJSONString(dst, message)
	dst = append(dst, '}', '}')
	return dst
}

// encodeCommitList appends a JSON array of commits from parallel sha/message slices.
func encodeCommitList(dst []byte, shas, messages []string) []byte {
	dst = append(dst, '[')
	for i := range shas {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = encodeCommit(dst, shas[i], messages[i])
	}
	return append(dst, ']')
}

// encodeContentFile appends a contents-API file object. contentB64 is the
// already base64-encoded file content.
func encodeContentFile(dst []byte, name, path, sha, contentB64 string, size int64) []byte {
	dst = append(dst, `{"type":"file","encoding":"base64","content":`...)
	dst = appendJSONString(dst, contentB64)
	dst = append(dst, `,"sha":`...)
	dst = appendJSONString(dst, sha)
	dst = append(dst, `,"size":`...)
	dst = appendJSONInt(dst, size)
	dst = append(dst, `,"name":`...)
	dst = appendJSONString(dst, name)
	dst = append(dst, `,"path":`...)
	dst = appendJSONString(dst, path)
	dst = append(dst, '}')
	return dst
}

// encodeContentEntry appends one directory-listing entry.
func encodeContentEntry(dst []byte, typ, name, path, sha string) []byte {
	dst = append(dst, `{"type":`...)
	dst = appendJSONString(dst, typ)
	dst = append(dst, `,"name":`...)
	dst = appendJSONString(dst, name)
	dst = append(dst, `,"path":`...)
	dst = appendJSONString(dst, path)
	dst = append(dst, `,"sha":`...)
	dst = appendJSONString(dst, sha)
	dst = append(dst, '}')
	return dst
}

// encodePRFile appends one pull-request file entry.
func encodePRFile(dst []byte, filename, status string, additions, deletions int) []byte {
	dst = append(dst, `{"filename":`...)
	dst = appendJSONString(dst, filename)
	dst = append(dst, `,"status":`...)
	dst = appendJSONString(dst, status)
	dst = append(dst, `,"additions":`...)
	dst = appendJSONInt(dst, int64(additions))
	dst = append(dst, `,"deletions":`...)
	dst = appendJSONInt(dst, int64(deletions))
	dst = append(dst, `,"changes":`...)
	dst = appendJSONInt(dst, int64(additions+deletions))
	dst = append(dst, '}')
	return dst
}
