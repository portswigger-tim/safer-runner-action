# L7 path + method filtering (`http-filter`)

**Status:** proposed — design only, not implemented. Tracking: [#17](https://github.com/portswigger-tim/safer-runner-action/issues/17).

## Why

v2 narrows egress to a set of allowlisted host *names*. It cannot judge *what* a request
does once the host is allowed, so **every allowlisted host is a full-capability channel** —
and the hosts a CI job must allow are exactly the trusted places you can also *write* to:

- `github.com` — a step can `git push` stolen data to an attacker-controlled repo.
- `registry.npmjs.org` — `npm publish` (an HTTP `PUT`) ships a package out.
- `pypi.org` / `upload.pypi.org` — a `twine upload` (`POST`) ships one out.
- `ghcr.io`, `registry-1.docker.io` — a `docker push` writes blobs out.
- `api.github.com` and REST APIs generally — a `POST`/`PUT` writes data out.

All of these pass the host check honestly. This is the residual the security review called out:
domain allowlisting controls *where* a job can talk, not *what it does there*.

Because the proxy TLS-terminates intercepted HTTPS, it already sees the request method, path,
Host and headers. `http-filter` is one more gate after the host check: on a host you choose,
allow only the methods and paths you name. The common shape is "make this trusted host
**read-only**" — installs and pulls (`GET`) yes, publishes and pushes (`PUT`/`POST`) no — which
blocks exfil to the very hosts you have to trust. It is a general mechanism; GitHub is one case,
not the point.

## Scope and non-goals

- **In scope:** intercepted HTTPS and plain HTTP on the runner, where the proxy sees the
  full request.
- **Not a data boundary.** Method/path filtering narrows *where and how* a step can write;
  it does not inspect bodies, so it cannot stop data smuggled inside an *allowed* write (or
  a small amount in a path/query). Same philosophy as the host allowlist — finer-grained,
  still not a seal.
- **Not for passthrough/container traffic.** SNI-only connections (`passthrough-domains`,
  and container HTTPS in enforce) expose no path, so they cannot be filtered until container
  TLS interception ships.

## How it layers on `allowed-domains`

`allowed-domains` stays the single source of truth for reachability (DNS + proxy SNI).
`http-filter` is **purely subtractive** — it only refines a host that is already allowed,
and can never widen access. Adding a filter therefore cannot silently open a new host.

| in `allowed-domains`? | in `http-filter`? | result |
|---|---|---|
| yes | no  | all requests allowed (today's behaviour) |
| yes | yes | **only what the filter permits** — an unmatched method/path is denied |
| no  | yes | **no access** — the filter is inert; the host is not reachable |
| no  | no  | no access (the default) |

A filtered host still resolves and connects (it passed the domain gate); the filter then
rejects the disallowed method/path at the HTTP layer. A non-allowed domain fails earlier,
at DNS/SNI.

## Config shape

`http-filter` is a map of host → (path pattern → allowed methods):

```yaml
with:
  mode: enforce
  allowed-domains: |
    registry.npmjs.org pypi.org files.pythonhosted.org
    github.com api.github.com
  http-filter: |
    registry.npmjs.org:
      "*": GET, HEAD                               # install yes, npm publish (PUT) no
    pypi.org:
      "*": GET, HEAD                               # metadata reads only
    api.github.com:
      "*": GET, HEAD                               # API read-only
    github.com:
      "*": "*"                                     # baseline: allow everything
      "*/git-receive-pack": NONE                   # deny all pushes…
      "portswigger-tim/*/git-receive-pack": "*"    # …except our org
```

### Conventions

1. **Naming a host makes it an allowlist.** Within a filtered host a request is allowed
   only if a rule matches its path *and* lists its method; anything unmatched is denied.
2. **Most-specific path wins.** `portswigger-tim/*/git-receive-pack` overrides the broader
   `*/git-receive-pack`, which overrides `*`. This is what makes carve-outs possible.
3. **Method tokens:** a comma list (`GET, POST`), `*` or `ALL` for any method, and `NONE`
   (equivalently an empty list) to deny a path. `NONE` is what lets you subtract one path
   from a `"*": "*"` baseline.
4. **One glob — the same `*` as `allowed-domains`.** There is no separate `**`. `*` works for
   paths exactly as it does for host names, with `/` in a path playing the role of `.` in a
   host: a standalone `*` segment spans any depth (`*/git-receive-pack` matches
   `owner/repo/git-receive-pack`, just as `*.nip.io` matches `a.b.c.nip.io`), and a `*` inside
   a segment matches within that segment (`pre*`, as in `productionresultssa*`). One behaviour
   across the whole config file.
5. Methods are matched case-insensitively; paths case-sensitively (URLs are). Matching is
   on the path; the query string is ignored (sufficient for the git case — see below).

### Guardrails

- **Inert filter:** if `http-filter` names a host that is not in `allowed-domains`, warn
  "this filter has no effect; add the host to `allowed-domains`." Catches typos and the
  mistaken belief that a filter grants access.
- **Passthrough host:** if a filtered host is in `passthrough-domains` (SNI-only), warn
  that it cannot be path-filtered, rather than silently ignoring the rule.

## Worked examples

### Make a trusted host read-only (the common case)

For package registries, container registries and REST APIs, read and write are cleanly
separated by method — installs/pulls are `GET`/`HEAD`, publishes/pushes are `PUT`/`POST`/`PATCH`.
So one line per host blocks exfil while leaving the job working:

```yaml
http-filter: |
  registry.npmjs.org:   { "*": GET, HEAD }   # npm install yes, npm publish no
  pypi.org:             { "*": GET, HEAD }    # pip reads metadata; upload.pypi.org not allowed at all
  files.pythonhosted.org: { "*": GET, HEAD }  # wheels/sdists download only
  ghcr.io:              { "*": GET, HEAD }     # docker pull yes, docker push no
  api.github.com:       { "*": GET, HEAD }     # no API writes (create repo, upload, issues…)
```

### Pin writes to specific repos (the hard case: git)

git is the one protocol here where a read and a write share a method — both `git-upload-pack`
(fetch) and `git-receive-pack` (push) are `POST` — so you cannot separate them by method; you
separate them by **path**:

```yaml
http-filter: |
  github.com:
    "*": "*"
    "*/git-receive-pack": NONE                   # block pushes generally…
    "portswigger-tim/*/git-receive-pack": "*"    # …except our org (most-specific wins)
```

To block *all* pushes, drop the last line.

## How git maps to paths

git over HTTPS is a fixed path scheme:

| operation | request |
|---|---|
| clone / fetch (read) | `GET /{owner}/{repo}.git/info/refs?service=git-upload-pack` → `POST …/git-upload-pack` |
| **push (write)** | `GET …/info/refs?service=git-receive-pack` → **`POST …/{owner}/{repo}.git/git-receive-pack`** |

So denying the `git-receive-pack` path stops a push while leaving clones and fetches
untouched — no body inspection required. SSH pushes are already blocked (only 80/443 are
proxied). Matching the POST path alone is enough; the discovery request's `service=` lives
in the query string, but blocking the POST is what stops the push.

## Analyze vs enforce, and the report

- **analyze:** log a `WOULD_BLOCK` for each method/path that enforce would refuse, so you
  can see what a filter would catch before turning it on.
- **enforce:** block with reason `method-not-allowed` / `path-not-allowed`, and surface the
  blocked request (method + redacted path) in the egress report with a suggested rule to
  add if the job genuinely needs it.

## Suggested `http-filter` (report)

The report should propose an `http-filter` from observed traffic, the way it already suggests
`allowed-domains`. The goal is a short, reviewable suggestion that encodes *intent* — "reads
open, writes only here" — not a dump of every URL seen. The method is observe → compress →
suggest, per host:

1. **Split reads from writes.** Reads (`GET`/`HEAD`/`OPTIONS`) are not the exfil surface;
   writes are. So reads **collapse to one line** — `"*": GET, HEAD` — and effort goes into
   the writes. For most hosts (npm, PyPI, registries, APIs) a job only reads, so the whole
   suggestion for that host is that single line.
2. **Template the write paths, don't list them.** Build a trie of the write paths and replace
   *variable* segments with `*`, keeping structural literals. "Variable" = numeric, hex/UUID,
   or high-cardinality at that position — exactly what `redact.ts`'s payload-looking-label
   detector already finds, so it is reused. (Bonus: the suggestion then never echoes ids or
   hashes, so reduction is also a redaction win.)
3. **Union the methods** per templated path.

Worked example — a job that reads npm + the API, and pushes to one repo, reduces to a few lines:

```yaml
http-filter:
  registry.npmjs.org:
    "*": GET, HEAD                        # install only
  api.github.com:
    "*": GET, HEAD                        # all API traffic was reads
  github.com:
    "*": "*"
    "*/git-receive-pack": NONE            # block pushes generally…
    "myorg/app/git-receive-pack": "*"     # …except where this job actually pushed
```

### The method-boundary trap

For most hosts read and write differ by method, so reduction is safe and trivial. The trap is a
host where they **share** a method: on `github.com` both fetch and push are `POST`, so a naive
`"*": GET, POST` would silently re-open pushes everywhere.

The reducer recognises these by a simple **path-suffix (`endsWith`) list** — start minimal,
seeded with the captured git pack URLs (`git-receive-pack`, `git-upload-pack`), and expand it
over time (registry blob/manifest uploads, PyPI `/legacy/`, …). A request whose path ends with a
listed suffix is kept **path-specific** rather than folded into the host's method baseline, and
the reducer **pins the owner/repo actually written to** (templating to `*` only when several are
seen). Keeping the list short and growing it as new sensitive endpoints come up is fine — a
missing suffix only makes a suggestion looser, never wrong at enforcement time (the user still
reviews it). Without this, the "reduction" would quietly defeat the feature.

### Granularity

Emit at a chosen level, and show the compression so a reviewer can judge it:

- **A — host method posture:** `host: { "*": <union of methods> }`. One line per host; loosest.
- **B — read/write split (default):** reads collapsed, writes templated shallow (the example above).
- **C — templated paths:** every path templated, depth-capped. Most precise, more lines.

Prefer the tightest level that still covers observed traffic. Head it with the compression
("collapsed 142 requests → 5 rules (level B); 1 write endpoint kept specific"), show it in
analyze (building the filter is the point) and on enforce blocks, and flag *"suggestion is
coarse — review"* when it had to generalize heavily. It is advisory — never auto-applied.

## Limitations (restated for the record)

- **Intercepted HTTPS + plain HTTP only.** A write from inside a container, or to any
  `passthrough-domains` host, is not filtered until container interception ships.
- **git-LFS / large uploads:** the pointer negotiation hits the API, but the object bytes go
  to a separate storage host — an LFS push is a gap unless that host is intercepted. The same
  applies to any registry that redirects uploads to a separate storage backend.
- **No body or query inspection** — a filter narrows the blast radius; it cannot stop data
  hidden inside an allowed write to an allowed path.
- **Path-scheme upkeep:** the matcher must tolerate the optional `.git` suffix and HTTP/2
  (`:path` / `:method` pseudo-headers; mitmproxy normalizes these) and any redirects on
  `.git` paths.

## Implementation sketch

- `proxy/policy_core.py`: a post-host gate. Compile `http-filter` into
  `host → ordered [(pattern, methods)]`, match the request method and path, and return
  allow/deny with a reason. A pure function — unit-testable alongside the existing Python
  tests. Reuse the `allowed-domains` matcher so `*` behaves identically.
- `src/policy.ts` / `policy.json`: build and carry the compiled rules.
- `src/inputs.ts`: parse and validate `http-filter`; emit the two guardrail warnings.
- `src/report.ts`: new blocked-reason rows and the "if the job needs it" suggestion. The
  suggestion reducer carries the sensitive-endpoint `endsWith` list (seeded with the git pack
  URLs, expandable) used to keep writes path-specific.

## Resolved decisions (RFC [#17](https://github.com/portswigger-tim/safer-runner-action/issues/17))

- **General-purpose, not GitHub-specific.** `http-filter` applies to every host (npm, PyPI,
  container registries, any REST API), so **no** GitHub-only convenience input (e.g.
  `write-repos`) — the general form already covers git, and sugar for one host would not fit
  a general mechanism.
- **No auto-allow of `$GITHUB_REPOSITORY`.** Writes must be listed explicitly; nothing is
  opened implicitly.
- **Report default granularity: B (read/write split).**
- **One glob.** `*` behaves exactly as in `allowed-domains` (`/` ↔ `.`); there is no `**`.
