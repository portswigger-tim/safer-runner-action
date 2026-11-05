# v2 release notes

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
`block-risky-github-subdomains`, `dns-servers`, `disable-sudo`, `docker`, `fail-on-tampering`.

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
