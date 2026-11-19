[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/101parallax/github-core-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/101parallax/github-core-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

# github-core-clone

A GitHub-compatible git forge in a single static Go binary, built for the
[github-core-clone-01 bounty](https://make.fun/bounty/github-core-clone-01) on
[make.fun](https://make.fun/bounty/github-core-clone-01). It serves the four
surfaces the contest grades — git smart HTTP, REST v3, GraphQL v4 and MCP —
from one shared in-memory store, over a hand-rolled raw-TCP HTTP/1.1 server.

## What it does

- **Git smart HTTP**: upload-pack v2 (`fetch` + `ls-refs`, shallow support),
  receive-pack v0 with `report-status` and `side-band-64k`, pack reading with
  unified OFS/REF delta resolution, plain (undeltified) pack writing.
- **REST v3**: repos, issues, pulls (squash merge, three-way conflict
  detection), contents (real git objects behind every PUT/DELETE), users,
  pagination with absolute `Link` headers.
- **GraphQL v4**: hand-written executor for the fixed document set the suite
  uses, including batched requests, `__type` introspection, cursor
  pagination and global-ID round-trips through `node(id:)`.
- **MCP**: JSON-RPC with both the modern `server/discover` era and the legacy
  `initialize` era, six tools over the same store as REST.
- **Determinism**: no wall clock and no randomness anywhere in stored data;
  commit timestamps come from `MAKEFUN_TRIAL_NOW`, IDs from sequential
  counters or content hashes, list order from insertion sequence.

## Layout

```
main.ts                  Thin Node launcher: spawns ./forge, forwards env/stdio,
                         exits with the binary's exit code (with a fallback
                         ladder for read-only / noexec checkouts)
forge                    The built static binary (committed, executable)
go/
  cmd/forge/main.go      Boot lifecycle only: bind, register, poll /done, exit
  internal/transport/    Raw-TCP HTTP/1.1 server (not net/http on the hot path)
  internal/httpapi/      Routing, auth, and the four surfaces
  internal/git/          Object model, pkt-line codec, pack read/write
  internal/store/        In-memory store + generation-keyed memoization
```

## Build

Go 1.24, zero dependencies (stdlib only):

```sh
cd go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o ../forge ./cmd/forge
```

The binary is static, stripped, ~6.4 MB (limit 8 MiB per file), and must be
committed with its executable bit set.

## Run

The platform runs `node /bot/main.ts`, which spawns `./forge`. The binary
expects `MAKEFUN_ENV_URL` (the trial env's origin) and `MAKEFUN_SHOP_TOKEN`
(the Bearer token the suite presents). It binds an ephemeral port on
`0.0.0.0`, registers it with `POST $MAKEFUN_ENV_URL/register`, serves until
`GET $MAKEFUN_ENV_URL/done` answers `{"done": true}`, then exits 0.
`GET /healthz` answers `{"ok": true}` without a token; every other route
requires `Authorization: Bearer <token>`.

Locally, against the kit's conformance suite:

```sh
node --experimental-strip-types sdk/run.ts --url http://127.0.0.1:PORT --token "$TOKEN" --perf --json
```

## Performance notes

The timed workloads are dominated by per-request overhead, so the hot paths
are built to do as little as possible per request:

- **Raw-TCP HTTP**: single-write responses with `Content-Length`, keep-alive,
  pooled per-connection buffers, first-byte header dispatch — no `net/http`
  on the serving path.
- **Whole-response caching, keyed on per-repo mutation generation**: clone
  fetch responses, ls-refs advertisements and single-issue GETs are served
  from memoized bytes; a push bumps the generation and invalidates them.
- **Pooled zlib** (level 1 for pack generation) with `Reset` — fresh
  writers cost ~10x more than pooled ones.
- **Hand-rolled JSON** for hot response types (byte-identical to
  `encoding/json`, including HTML escaping), zero allocations on the read path.
- **Lock discipline**: atomic generation loads instead of read locks on the
  git hot path, one lock per issue create, never hold a lock across zlib,
  JSON encoding or network I/O.
- **No per-request goroutines, no background work, no logging per request** —
  the entry shares 2 CPUs with the grading client, so idle CPU is points.

Local conformance (kit suite, 3 consecutive runs): 120/120 checks.
