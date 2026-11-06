# L7 path + method filtering (`http-filter`)

**Status:** proposed — design only, not implemented. Tracking: [#17](https://github.com/portswigger-tim/safer-runner-action/issues/17).

## Why

v2 narrows egress to a set of allowlisted host names. It cannot judge *what* a request
does once the host is allowed, so an allowlisted host is a full-capability channel: a
malicious step can push stolen data to an attacker-owned repository on `github.com`, or
write it through `api.github.com`, and both pass the host check honestly. This is the
residual called out in the security review.

Because the proxy TLS-terminates intercepted HTTPS, it already sees the request method,
path, Host and headers. `http-filter` is one more gate after the host check: on a host you
choose, allow only the methods and paths you name.

The headline use case: **restrict `git push` to known repositories** — deny the
`git-receive-pack` path except for an allowlisted owner/repo — while clones, fetches and
API reads keep working.

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
  allowed-domains: github.com api.github.com
  http-filter: |
    github.com:
      "**": "*"                                    # baseline: allow everything
      "*/git-receive-pack": NONE                   # deny all pushes…
      "portswigger-tim/*/git-receive-pack": "*"    # …except our org
    api.github.com:
      "**": GET, HEAD                              # API is read-only
```

### Conventions

1. **Naming a host makes it an allowlist.** Within a filtered host a request is allowed
   only if a rule matches its path *and* lists its method; anything unmatched is denied.
2. **Most-specific path wins.** `portswigger-tim/*/git-receive-pack` overrides the broader
   `*/git-receive-pack`, which overrides `**`. This is what makes carve-outs possible.
3. **Method tokens:** a comma list (`GET, POST`), `*` or `ALL` for any method, and `NONE`
   (equivalently an empty list) to deny a path. `NONE` is what lets you subtract one path
   from a `**: "*"` baseline.
4. **Globbing:** `*` matches within a path segment; `**` matches across `/`. git needs
   across-segment matching (`*/git-receive-pack` spans `owner/repo`), so use `**` or a
   greedy `*`; `**` is documented to avoid surprise.
5. Methods are matched case-insensitively; paths case-sensitively (URLs are). Matching is
   on the path; the query string is ignored (sufficient for the git case — see below).

### Guardrails

- **Inert filter:** if `http-filter` names a host that is not in `allowed-domains`, warn
  "this filter has no effect; add the host to `allowed-domains`." Catches typos and the
  mistaken belief that a filter grants access.
- **Passthrough host:** if a filtered host is in `passthrough-domains` (SNI-only), warn
  that it cannot be path-filtered, rather than silently ignoring the rule.

## Worked examples

**API read-only — blocks API-based exfil (create repo, upload, issues, …):**
```yaml
http-filter: |
  api.github.com:
    "**": GET, HEAD
```

**Block all git pushes, keep clones/fetches/reads:**
```yaml
http-filter: |
  github.com:
    "**": "*"
    "*/git-receive-pack": NONE
```

**Push only to our org (the headline case):**
```yaml
http-filter: |
  github.com:
    "**": "*"
    "*/git-receive-pack": NONE
    "portswigger-tim/*/git-receive-pack": "*"
```

## Why this maps cleanly to git

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
   writes are. So reads **collapse to one line** — `"**": GET, HEAD` — and effort goes into
   the writes.
2. **Template the write paths, don't list them.** Build a trie of the write paths and replace
   *variable* segments with `*`, keeping structural literals. "Variable" = numeric, hex/UUID,
   or high-cardinality at that position — exactly what `redact.ts`'s payload-looking-label
   detector already finds, so it is reused. (Bonus: the suggestion then never echoes ids or
   hashes, so reduction is also a redaction win.)
3. **Union the methods** per templated path.

Worked example — a job that clones one repo, pushes to another, and reads the API (8 distinct
requests) reduces to about five lines:

```yaml
http-filter:
  api.github.com:
    "**": GET, HEAD                       # all API traffic was reads
    "repos/*/*/statuses/*": POST          # the one write kind seen (sha templated)
  github.com:
    "**": "*"
    "*/git-receive-pack": NONE            # block pushes generally…
    "myorg/app/git-receive-pack": "*"     # …except where this job actually pushed
```

### The method-boundary trap

Do not collapse across a method boundary where a read and a write **share** a method. On
`github.com` both fetch and push are `POST` (`git-upload-pack` vs `git-receive-pack`), so a
naive `"**": GET, POST` would silently re-open pushes everywhere. The reducer keeps a small
set of **known-sensitive endpoints** (git `git-receive-pack`, release/asset uploads) always
path-separable, and **pins the owner/repo actually written to** (templating to `*` only when
several are seen). Otherwise the "reduction" quietly defeats the feature.

### Granularity

Emit at a chosen level, and show the compression so a reviewer can judge it:

- **A — host method posture:** `host: { "**": <union of methods> }`. One line per host; loosest.
- **B — read/write split (default):** reads collapsed, writes templated shallow (the example above).
- **C — templated paths:** every path templated, depth-capped. Most precise, more lines.

Prefer the tightest level that still covers observed traffic. Head it with the compression
("collapsed 142 requests → 5 rules (level B); 1 write endpoint kept specific"), show it in
analyze (building the filter is the point) and on enforce blocks, and flag *"suggestion is
coarse — review"* when it had to generalize heavily. It is advisory — never auto-applied.

## Limitations (restated for the record)

- **Intercepted HTTPS + plain HTTP only.** A push from inside a container, or any
  `passthrough-domains` host, is not filtered until container interception ships.
- **git-LFS:** the pointer negotiation hits the API, but the object bytes go to a separate
  storage host — an LFS push is a gap unless that host is intercepted.
- **No body or query inspection** — a filter narrows the blast radius; it cannot stop data
  hidden inside an allowed write to an allowed path.
- **Path-scheme upkeep:** the matcher must tolerate the optional `.git` suffix and HTTP/2
  (`:path` / `:method` pseudo-headers; mitmproxy normalizes these) and any redirects on
  `.git` paths.

## Implementation sketch

- `proxy/policy_core.py`: a post-host gate. Compile `http-filter` into
  `host → ordered [(pattern, methods)]`, match the request method and path, and return
  allow/deny with a reason. A pure function — unit-testable alongside the existing Python
  tests.
- `src/policy.ts` / `policy.json`: build and carry the compiled rules.
- `src/inputs.ts`: parse and validate `http-filter`; emit the two guardrail warnings.
- `src/report.ts`: new blocked-reason rows and the "if the job needs it" suggestion.

## Open questions

- Keep a GitHub-aware convenience input (for example `write-repos: owner/repo`) as sugar
  that expands into the `git-receive-pack` rules above, or expose only the general
  `http-filter`? The general form already covers the case; sugar is optional polish.
- Auto-allow the running workflow's own repository (`$GITHUB_REPOSITORY`) for pushes, so
  "push to self" needs no configuration.
