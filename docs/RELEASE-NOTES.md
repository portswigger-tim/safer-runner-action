# v2 release notes

## v2.4.0 (unreleased)

Sudo and docker get the analyze-then-enforce flow the egress allowlist and `http-filter` already
have: `analyze` never changes either, and reports what `enforce` would block.

- **New `sudo-config` input.** With sudo removed in `enforce`, the job may still run these exact
  sudo command lines as root (a YAML list, on top of the action's own read-only checks). The
  input is parsed strictly and fails the step on anything it cannot express exactly. Any
  `sudo-config` labels the job **ADVISORY**: a command that can run code or write files gives
  the job root. The v1 `sudo-config` format is not accepted.
- **`analyze` reports and suggests for sudo.** The summary lists the sudo commands `enforce`
  would block under your `disable-sudo` / `sudo-config`, and suggests a `sudo-config` built from
  the job's own sudo use (exact lines only; secret-looking arguments are left out). Best effort:
  the sudo log does not show `sudo -E` or argument boundaries, so check the job under `enforce`.
- **Behaviour change: `mode: analyze` never changes sudo.** `disable-sudo: true` in `analyze`
  now reports what enforce would block and suggests a `sudo-config`, instead of removing sudo.
  To remove sudo, use `mode: enforce`.
- **`disable-sudo` defaults to `true` in both modes.** In `analyze` this changes nothing on the
  runner (analyze only evaluates it); in `enforce` it is the same as before.
- **`sudo-config` with `disable-sudo: false` is rejected** (sudo is kept, so the list would have
  no effect).
- **Behaviour change: `mode: analyze` never changes docker access.** `docker: remove-group` or
  `docker: stop` in `analyze` is now evaluated, not applied (setup warns), and docker stays usable
  for the job. To remove docker access, use `mode: enforce`.
- **`docker` defaults to `remove-group` in both modes.** In `analyze` this changes nothing on the
  runner (analyze only evaluates it); in `enforce` it is the same as before.
- **`analyze` reports and suggests for docker.** It records the job's use of docker after setup
  (read only) and the summary lists what `enforce` would block under your `docker` setting, then
  suggests one: a job that uses docker needs `docker: keep` (ADVISORY), and `docker: stop` that
  would stop service containers is flagged. Only kinds, counts and image names are shown. Best
  effort: in `analyze` the job has docker, so it can stop the recording.
- **Hardening:** redact sudo arguments in the job summary and log.
- **Hardening:** reject repeated wildcards in a domain label.
- **A shorter job summary.** It opens with a scorecard and, in `analyze`, one Suggested Enforce
  Configuration block to paste (the inputs this job needs to run under `enforce`; ADVISORY
  settings are marked). Network, sudo and docker details follow, with what the action itself did
  collapsed under Runner System. The suggested `uses:` line keeps the repository and ref the
  workflow used.

## v2.3.0

Internal refactors and stricter, standards-based `http-filter` parsing. No new inputs.

- **`http-filter` is parsed with a standard YAML library and a strict schema.** Errors are
  clearer and name the line, and an ambiguous or malformed filter is rejected (fails closed)
  rather than guessed at — duplicate host or path keys, unexpected structure, and non-string
  methods are now caught.
- **The suggester and the enforcing engine are unified.** The logic that turns observed traffic
  into a suggested `http-filter` now shares the proxy's own matcher, so a suggestion always
  matches what enforcement would do. The suggestions you see for a given job are unchanged.
- **Stricter validation of the internal policy file**, which now fails closed on an unexpected
  shape.
- Documentation refreshed (CLAUDE.md and the design notes) to the current v2 architecture.

## v2.2.1

Hardening for the `http-filter` feature in v2.2.0. No input changes; drop-in.

- **Tighter path matching.** On `github.com`, git paths are matched with or without the `.git`
  suffix and case-insensitively for the owner/repo, and repeated slashes, `;`-parameters and
  encoded path-traversal forms are refused — so a deny rule cannot be slipped by an alternate
  spelling. To deny a repository's writes, name the endpoint — `owner/repo/git-receive-pack:
  NONE` — rather than `owner/repo/*` (a longer-literal allow elsewhere can otherwise outrank a
  short wildcard deny).
- **The job summary no longer prints refused request paths.** A blocked request is shown by host,
  method and reason only (the path as `‹path hidden›`), and a non-standard method as `INVALID`, so
  a crafted path or method cannot carry data into the public summary. To learn what to allow, run
  the host in `analyze` without its `http-filter` entry and use the suggested filter.
- **The built-in GitHub platform allowlist is split into essential and optional.** Job lease and
  completion, OIDC, the live-log stream and log metadata are always allowed, so filtering a GitHub
  host never hangs the job. Artifact, cache, step-status and stored-log traffic are optional and
  yield to an explicit user rule. An explicit `NONE` on `results-receiver.actions.githubusercontent.com`
  or the `productionresultssa*.blob.core.windows.net` storage host can therefore drop that job's
  stored logs, step summary, status, artifacts and cache — the job still completes.
- **`pre` fails closed on an invalid `http-filter`.** In `enforce`, a malformed filter now fails
  the job at setup rather than continuing.

## v2.2.0

New: **`http-filter`** — restrict an allowlisted host by HTTP method and path. No changes to
existing inputs; drop-in for v2.1.0.

- **`http-filter`** (new input): on a host already in `allowed-domains`, allow only the methods
  and paths you name — make a package host or API read-only (`"*": GET, HEAD`), or allow
  `git push` only to specific repos while clones and reads keep working. It is purely subtractive
  (it never widens access) and applies to intercepted HTTPS and plain HTTP. `*` is the same glob
  as `allowed-domains`. See
  [docs/HTTP-FILTER.md](HTTP-FILTER.md).
- **`allow-github-platform`** (new input, default `true`): an explicit built-in allowlist that
  keeps the Actions platform working when you filter a GitHub host — step logs, status, artifact
  and cache uploads, OIDC, and job lease renewal / completion. Set it `false` for a hard lockdown.
- The egress report lists requests the filter refused and suggests an `http-filter` to add.
- On `github.com`, git paths are matched with or without the `.git` suffix and case-insensitively
  for the owner/repo, so a deny cannot be slipped by spelling. Paths are otherwise case-sensitive.

## v2.1.0

Security hardening and report accuracy. No input changes — drop-in for v2.0.0.

- **Container firewall fails closed in enforce.** If Docker is running but the expected
  `DOCKER-USER` hook is missing (a non-standard firewall backend), setup now aborts in enforce
  instead of continuing without container rules. Analyze still only warns. Standard
  GitHub-hosted runners are unaffected.
- **Tighter report redaction, honest wording.** Every label of a blocked hostname is now
  checked (the earlier short-label and trailing-label gaps are closed). The caveat states
  plainly that redaction is best effort, not a guarantee: data shaped to evade it can reach the
  summary and job log whole, even through a single refused hostname. Treat the raw
  `/var/log/safer-runner` logs (including `proxy-flows.jsonl`) as unredacted.
- **Post-run integrity is labelled advisory.** The summary no longer shows "boundary intact" on
  the strength of a check a malicious step could suppress. It shows "controls applied at setup"
  plus a separate post-run status chip (advisory / tampered / unverified). Enforcement never
  depended on the post step.
- **Report tidy-up.** The "Subdomains of exact entries" section is removed; refused subdomains
  of exact entries are still listed under Diagnostics → DNS refused.
- **New: [docs/CICD-GOOD-PRACTICE.md](CICD-GOOD-PRACTICE.md)** — defence-in-depth practices for
  hardening pipelines around this action, linked from the README.
- **Fix:** the scheduled GitHub-domains updater now targets `main` (the `v2` branch was removed
  at GA).

## v2.0.0

**Breaking: a smaller input surface.** Workflows that set any of the
removed inputs must be updated; the action fails setup on an unknown `docker:` value and on a
`dns-servers:` entry that is not an IP address. The runner warns about removed inputs it no
longer recognises ("Unexpected input"), but does not fail on them, so check your `with:` blocks.

### Migration (old input → new)

| v2 beta | v2.0.0 |
|---|---|
| `disable-docker: true` | `docker: remove-group` (what enforce does — can be dropped in enforce) |
| `disable-docker: false` | `docker: keep` (in enforce the job is now labelled **ADVISORY**) |
| `stop-docker: true` | `docker: stop` |
| `primary-dns-server: A` + `secondary-dns-server: B` | `dns-servers: A B` (first = primary, the rest tried in order; empty = Quad9) |
| `secondary-dns-server: ''` (no secondary) | `dns-servers: A` |
| `sudo-config: …` | **removed.** sudo is on/off: drop it (enforce removes sudo) or set `disable-sudo: false` (ADVISORY) |
| `proxy-port: N` | **removed.** A free port pair in 20000–32766 is always picked at setup |
| `proxy-stream-large-bodies: …` | **removed.** Internal constant (`1m`) |
| `container-tls: …` | **removed.** Container HTTPS is always checked by name (SNI); `intercept` was never implemented and returns when CA injection into containers ships |
| `fail-on-tampering` unset | enforce now fails the job on tampering (analyze still never does). Set `fail-on-tampering: false` to keep the old enforce behaviour |

Final inputs: `mode`, `allowed-domains`, `passthrough-domains`,
`block-risky-github-subdomains`, `dns-servers`, `disable-sudo`, `docker`, `fail-on-tampering` (at v2.0.0;
`http-filter` and `allow-github-platform` were added in v2.2.0).

### What each mode does

| | analyze (default) | enforce |
|---|---|---|
| `disable-sudo` | `false` | `true` |
| `docker` | `keep` | `remove-group` |
| `fail-on-tampering` | `false` | `true` |

An explicit value always wins. Unchanged: `mode: analyze`, `block-risky-github-subdomains: true`,
`passthrough-domains: hosted-compute-*.githubapp.com`, `dns-servers` = Quad9.

### Docker removal is now verified and fails closed (enforce)

- `docker: keep` under enforce labels the job **ADVISORY** (summary title, chip, warning), the
  same as retained sudo: docker access is root-equivalent.
- After `remove-group` / `stop`, the action checks the runner's real docker access (daemon and
  socket unit active, runner in the docker group, socket usable by the job's process). If the
  runner can still use docker, **enforce fails setup** instead of continuing with a reversible
  boundary; analyze warns. Previously a failed removal was only a warning.
- The job summary's Diagnostics shows the **verified** docker state, not the input value.

### Other changes

- `fail-on-tampering` is resolved at setup and recorded in the root-owned setup marker, and the
  post step checks integrity before building the report, so a report error can no longer skip
  the failure.
- CoreDNS forwards to the `dns-servers` in order (`policy sequential`) so the first entry really
  is the primary.
