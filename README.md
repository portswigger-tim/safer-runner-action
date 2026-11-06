# Safer Runner Action — v2

> **This is v2 — a major rewrite, not an upgrade of v1.** It is a new architecture; pin a v2
> version explicitly (there is no moving `@v2` tag). v1 remains on `@v1`. Design:
> [docs/DESIGN-v2.md](docs/DESIGN-v2.md); decisions: [docs/V2-P1-NOTES.md](docs/V2-P1-NOTES.md).

Egress control for GitHub-hosted Ubuntu runners, enforced on **hostnames** rather than IP
addresses. All HTTP and HTTPS from the job is forced through a TLS-terminating proxy
(mitmproxy). The proxy checks the TLS SNI and every request's `Host` against an allowlist and
connects to the name itself, never to the IP the client chose.

Allowlisting by IP address admits every tenant of a shared CDN or cloud range:
`curl --resolve attacker.example:443:<allowed-ip>` reaches an attacker-controlled site with a
valid certificate. Filtering on hostnames closes that.

## Usage

Put it **first** in the job. Its `pre` step applies the policy before any other step runs,
including other actions' `pre` steps.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: portswigger-tim/safer-runner-action@v2.0.0 # pin an exact version or SHA — v2 has no moving @v2 tag
        with:
          mode: enforce
          allowed-domains: |
            registry.npmjs.org
            pypi.org
            files.pythonhosted.org
            .docker.io        # docker.io and all of its subdomains
          # enforce removes sudo + the docker group and fails on tampering.
          # `disable-sudo: false` / `docker: keep` opt out, but make enforce ADVISORY.
      - uses: actions/checkout@v5
      - run: npm ci
```

> [!IMPORTANT]
> **Upgrading from a v2 beta?** The input surface changed before v2.0.0: `docker:` replaces
> `disable-docker` / `stop-docker`, `dns-servers:` replaces `primary-dns-server` /
> `secondary-dns-server`, and `sudo-config`, `proxy-port`, `proxy-stream-large-bodies` and
> `container-tls` are gone. See [docs/RELEASE-NOTES.md](docs/RELEASE-NOTES.md#v200) for the old → new mapping.

To work out what a job needs, start with `mode: analyze` (the default). Nothing is blocked.
The job summary lists every host the job contacted, marks the ones enforce mode would block,
and suggests an `allowed-domains` block.

The summary leads with a verdict and groups blocked traffic by cause: **bypass attempts**
(Host/SNI mismatch, or an allowlisted name resolving to an internal address) first, then
hosts **not on the allowlist** (with YAML to paste), then traffic with **no hostname**.
Allowed traffic is split into the job's own hosts and GitHub platform traffic (collapsed),
and self-tests, non-proxied packets, DNS refusals, sudo use and the config check sit in one
collapsed **Diagnostics** section. Totals count only traffic that was actually allowed, and
passthrough hosts (never decrypted) show `n/a` rather than a byte count.

GitHub's own endpoints come from `api.github.com/meta` (`.domains.actions`) at runtime, with a
generated snapshot as the offline fallback, so the runner, `actions/checkout`, artifacts and
caches work without configuration.

## Allowlist syntax: exact by default

The same patterns drive the proxy **and** DNS, so the two never disagree:

| Entry | Allows | Example |
|---|---|---|
| `example.com` | **exactly** `example.com` — not `www.example.com` | `pypi.org` |
| `*.example.com` | every subdomain, any depth — not `example.com` itself | `*.nip.io` |
| `.example.com` | shorthand for `example.com` + `*.example.com` | `.docker.io` |
| `pre*.example.com` | `*` within one label | `productionresultssa*.blob.core.windows.net` |

> [!TIP]
> To allow a name **and** its subdomains, write it as `.example.com` — a bare entry is that name
> only. In analyze mode, and in enforce when something is refused, the summary's **Subdomains of
> exact entries** section lists the lookups an exact entry blocks and suggests the `*.parent`
> entry to add.

Why: DNS answers for every name under an allowlisted zone used to be forwarded upstream, so
`<secret>.allowed.example` carried data to whoever runs that zone's name servers. Now a name
under an exact entry is answered NXDOMAIN **on the runner** and never sent anywhere. Wildcard
entries (`*.x`, `.x`) remain a DNS channel to that zone **by design** — use them only for zones
you trust, and prefer exact names. GitHub's own wildcards are the three `api.github.com/meta`
lists (`*.github.com`, `*.githubapp.com`, `*.actions.githubusercontent.com`).

## What enforce mode does

| Traffic | Result |
|---|---|
| HTTPS to an allowlisted name | TLS terminated with a per-run CA; each request's `Host` must equal the SNI |
| HTTPS to any other name, no SNI, or an IP literal | Closed at the ClientHello. No upstream connection is opened |
| `--resolve allowed.name:443:<any IP>` | The proxy connects to the real `allowed.name`; the client's IP is ignored |
| Domain fronting (`Host` ≠ SNI) | HTTP 403 |
| Plain HTTP | Decided by `Host`; the upstream is the `Host` name, never the client's IP |
| DNS to any server (`@8.8.8.8`, `@168.63.129.16`, ...) | Answered by the local resolver (CoreDNS). Only allowlisted names are forwarded upstream; everything else — including `<anything>.example.com` when only `example.com` is listed — gets NXDOMAIN on the runner |
| An allowlisted name that resolves to an internal address (IMDS `169.254.169.254`, loopback, RFC 1918, CGNAT `100.64/10`, Azure wireserver, IPv6 ULA / link-local) | Refused by the proxy, which resolves every upstream once, refuses internal addresses (the summary shows which address) and connects to the address it checked (no second lookup) |
| Any other TCP/UDP port, ICMP, IPv6 | Rejected |
| A hole in the redirect (proxy bypassed) | Still rejected by the filter (fail closed) |

Every job verifies three things on the live runner before any other step runs: an SNI-level
block actually fires, the proxy ignores the client's chosen IP, and the resolver refuses a
random name under an exact allowlist entry. In enforce mode the job fails if any check fails.

## Inputs

| Input | Default | |
|---|---|---|
| `mode` | `analyze` | `analyze` or `enforce` |
| `allowed-domains` | | `example.com` = exactly that name; `*.example.com` = subdomains only; `.example.com` = both; `a-*.example.com` = wildcard within one label (see [Allowlist syntax](#allowlist-syntax-exact-by-default)). Shared namespaces such as `blob.core.windows.net` are refused |
| `passthrough-domains` | `hosted-compute-*.githubapp.com` | Hosts checked by SNI only (not decrypted), same syntax. Use only for single-tenant hosts whose clients can't trust the CA. The default is always included |
| `block-risky-github-subdomains` | `true` | Deny `gist.github.com`, `gist.githubusercontent.com`, `raw.githubusercontent.com` |
| `dns-servers` | `9.9.9.9 149.112.112.112` (Quad9) | Upstream resolvers CoreDNS forwards allowlisted names to: IP addresses, space/comma/newline separated. The first is the primary, the rest are tried in order. Empty = the default |
| `disable-sudo` | follows `mode` | `enforce` removes the runner's sudo after setup; `analyze` keeps it. Set `true`/`false` to override; keeping sudo in enforce labels the job **ADVISORY** |
| `docker` | follows `mode` | `enforce` removes docker access (`remove-group`); `analyze` keeps it (`keep`). `keep`: leave docker alone. `remove-group`: take the runner out of the docker group and lock the socket to root. `stop`: stop and disable the docker daemon. In enforce, `keep` makes the job **ADVISORY**, and a removal that doesn't take effect fails the job |
| `fail-on-tampering` | follows `mode` | `enforce` fails the job (post step) if the safer-runner configuration changed during the job; `analyze` never breaks a build. The baseline is stored root-owned (`/etc/safer-runner/validation-state.json`). Advisory: see [Limitations](#limitations-read-these) |

An explicit value always wins; leaving one unset follows the mode. The proxy's ports (a free pair in
20000–32766, picked at setup) and its streaming threshold are internal; HTTPS from containers
is always checked by name (see [Containers](#containers)).

### What enforce changes (and how to opt out)

| | `mode: analyze` (default) | `mode: enforce` | Opt out in enforce |
|---|---|---|---|
| sudo | kept | **removed** (only the action's read-only checks stay) | `disable-sudo: false` → ADVISORY |
| docker | `keep` | **`remove-group`**, verified on the runner; fails the job if it doesn't take | `docker: keep` → ADVISORY |
| `fail-on-tampering` | off (analyze never breaks a build) | **on** | `fail-on-tampering: false` |
| Traffic off the allowlist | logged, not blocked | blocked | — |

"ADVISORY" means the egress controls were applied but a step could have used root
(sudo, or docker, which is root-equivalent) to remove them: the run log warns and the job
summary header reads *"enforce (ADVISORY — sudo/docker retained, not an enforced boundary)"*.

After `remove-group` or `stop`, the action verifies on the runner that docker is really gone —
daemon and socket-unit state, the runner's groups, and whether the job's process can still open
the socket — and records it in the summary's Diagnostics. If the removal did not take, enforce
fails the job. Removing sudo leaves only the action's read-only validation commands and its
post-step CA teardown. Analyze keeps both and reports any sudo the job used, so you see it before
you enforce.

## CA trust

The per-run CA is added to the system store, so curl, wget, git, Python's `ssl`, .NET (the
runner itself) and Docker pulls trust it. The action also exports `NODE_EXTRA_CA_CERTS`,
`NODE_USE_SYSTEM_CA`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `SSL_CERT_FILE`, `GIT_SSL_CAINFO`,
`AWS_CA_BUNDLE` and `CURL_CA_BUNDLE` to later steps, and imports the CA into every JDK on the
image. The private key exists only on tmpfs, readable only by the proxy user, and the post
step deletes it.

## Containers

Containers on the runner — `services:`, `docker run`, compose, testcontainers, `docker build`
RUN steps — get the same policy as the host, through the same proxy and DNS filter:

- Their DNS is answered by the action's resolver (denied names: NXDOMAIN), whatever resolver
  the container is configured with.
- Their HTTP/HTTPS (TCP 80/443) goes to the proxy; anything else they send off the runner is
  **rejected** in enforce (logged in analyze). Container ↔ container and container → runner
  traffic is not touched.
- **HTTPS from containers is checked by name (SNI)**: an
  allowlisted name is passed through without decryption, to the address the proxy resolved,
  so containers need **no CA** and nothing in the image changes. Non-allowlisted names are
  still blocked. Plain HTTP is checked by `Host` as on the host. Multi-tenant front doors
  (Azure Storage, `*.blob.core.windows.net` etc.) stay intercepted for containers in enforce,
  so they need the CA there (see Limitations).
- Host traffic is unchanged: always intercepted.
- The container rules hook Docker's `DOCKER-USER` iptables chain. If Docker is running without
  it (started with `iptables: false`, or another firewall backend), enforce **fails setup**
  rather than leave containers unfiltered; use `docker: stop` if the job doesn't need Docker.
  Analyze warns and carries on without container monitoring.
- When Docker already pulled images before the action (any job with `services:`), the action
  restarts `dockerd` once (with `live-restore`, so service containers keep running) so that
  later `docker pull`s trust the CA.
- The job summary has a **Container egress** section: what each container reached or was
  refused, by container name when docker is still accessible to the post step.

## Verifying this action (supply chain)

This action's `pre` step runs as root and installs root-owned binaries, so a tampered release
of it would own your runner. Treat it like any other privileged dependency.

**Pin it by full commit SHA**, not a tag or branch. Tags can be moved, and there is no moving
`@v2` tag. Keep the version in a comment so Dependabot or Renovate can update it:

```yaml
- uses: portswigger-tim/safer-runner-action@<40-char commit SHA> # v2.0.0
```

**Check the build provenance** of the commit you pin. Releases from the
[release workflow](.github/workflows/release.yml) onward carry a signed
[build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
for the files the runner executes (`action.yaml`, `dist/**`, `proxy/policy.py`,
`proxy/policy_core.py`). It is only produced after the release workflow has checked that the
tag is on a release branch, the tests pass, and a clean rebuild of `dist/` from the tagged
source is byte-identical to the committed `dist/`. Earlier tags have no attestation.

```bash
REPO=portswigger-tim/safer-runner-action
SHA=<the commit you pin>
git clone --quiet https://github.com/$REPO && cd safer-runner-action && git checkout --quiet "$SHA"
for f in action.yaml dist/*/index.js proxy/policy.py proxy/policy_core.py; do
  gh attestation verify "$f" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release.yml" \
    --source-digest "$SHA" --deny-self-hosted-runners || echo "NOT VERIFIED: $f"
done
```

A passing check means those exact files were built and checked by this repository's release
workflow from that commit. It does not prove the source is safe, and a missing or failing
attestation on a new tag means: don't use it, and please [report it](SECURITY.md).

**Run it alongside supply-chain-aware defaults.** It limits where a compromised dependency
can send data; these limit what that dependency can reach in the first place:

- Least-privilege `permissions:` at the top of every workflow (start from `contents: read`)
  and grant more per job.
- `npm ci --ignore-scripts` (and equivalents) where your build doesn't need install scripts.
- Don't share caches between untrusted jobs (PRs) and release/publish jobs: use distinct
  cache keys, or no cache, for anything that publishes.
- Put publish and deploy jobs that use OIDC (`id-token: write`) behind a protected
  [environment](https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment)
  with required reviewers, and scope the cloud-side trust policy to that environment.

## Limitations (read these)

- **`disable-sudo: false` or `docker: keep` makes enforce advisory.** Any step with root can
  remove the proxy and firewall, and docker group membership is root-equivalent. Both are
  removed by enforce; the summary labels the job ADVISORY when either was kept.
- **The job summary and the tamper check are advisory.** They come from the post step, which
  runs as the runner user from the action's files on the runner, and the job's own steps can
  modify those. A malicious step could alter or suppress the summary, the tamper check and
  `fail-on-tampering`. Treat them as a tripwire and a record, not tamper-proof evidence. The
  egress controls themselves (proxy, DNS, firewall, sudo and docker removal) are root-owned and
  don't depend on the post step. See [docs/DESIGN-post-run-integrity.md](docs/DESIGN-post-run-integrity.md).
- **Allowlisted names that resolve to internal addresses are refused.** That includes hosted
  runners with Azure private networking that reach private services by name. Such names
  can't be allowlisted in enforce yet.
- **Wildcard entries are a DNS channel by design.** `*.example.com` forwards every lookup under
  it, so whoever runs `example.com`'s name servers sees `<anything>.example.com`. Exact entries
  aren't.
- **Blocked names are redacted, best effort.** A refused name can be the payload
  (`<base64 secret>.attacker.example`). GitHub already masks a registered secret's literal value,
  so the summary and job log also hide hostname labels that look *encoded* (hex and digit runs of
  6+ characters; base32/64-looking labels of 8+: few vowels, scattered digits) as `‹redacted›`,
  without their length. Every label is checked, the domain and TLD included; only the
  allowlisted parent from your own configuration is always shown. This keeps long encoded values
  out of the report, but short or word-like labels are caught only part of the time, so a step
  that deliberately spreads data over many refused names can still get some of it into the
  summary. The raw logs on the runner (`/var/log/safer-runner/`, including `proxy-flows.jsonl`)
  are **not** redacted: don't upload them as artifacts from a public repository.
- **No DNS-rebinding protection for clients outside the proxy.** The resolver returns internal
  answers as-is; the proxy refuses them for all proxied traffic. A process that dials a
  loopback, docker-bridge or IMDS address by name gets no more than it could by IP literal
  (those addresses are reachable directly by design), but a browser-style rebinding attack on a
  local service inside the job is not prevented.
- **Allowlisted hosts are full-capability channels.** If `github.com` is allowed, a malicious
  step can push data to a repository it controls. v2 narrows egress to names; it can't judge
  what a request does.
- **Only TCP 80/443 is proxied.** In enforce, other ports are rejected, including SSH
  (`git@github.com`).
- **Containers are a boundary only when docker is removed** (which enforce does). With
  `docker: keep` any step can `docker run --privileged --network host` and leave the
  controls behind: the container rules then protect against dependencies running inside
  containers, not against a determined step (the summary warns that docker was retained).
- **Container HTTPS is checked by name only (SNI), trading the Host check for compatibility.**
  The proxy sees only the TLS name, so a container can reach another site served by the same
  front end as an allowlisted name (domain fronting) — the same trade-off as
  `passthrough-domains`. Azure Storage front doors are excluded (intercepted, Host-checked), so
  containers that talk to an allowlisted storage account in enforce need the CA
  (`/etc/safer-runner/ca.pem`) or must do it from a step on the runner. Container HTTPS is not
  path-logged.
- **Job containers (`container:`) are not supported.** The action would run inside the
  container and cannot control the runner: enforce fails with an explanation, analyze warns
  and monitors nothing. Run the job on the runner and use `services:` and `docker run` steps.
- **Docker container actions (`uses: docker://…`, Dockerfile actions) don't run when enforce
  has removed docker from the runner user** (the runner starts them as that user). Use
  `docker: keep` for such jobs (docker is then root-equivalent, see above). The
  runner's end-of-job cleanup of service containers also logs a harmless permission warning.
- **`docker build`**: RUN steps get container-path filtering; allowlisted HTTPS works by
  SNI without a CA. To intercept inside a build, `COPY` or secret-mount the CA yourself.
- **IPv6 container networks** are rejected in enforce (there is no IPv6 path through the proxy).
- **Clients that pin certificates, or that ignore both the system store and the variables
  above, fail** on allowlisted hosts. Fix: add the host to `passthrough-domains`, but only if it
  is single-tenant.
- **JDKs installed after this action** (for example by `actions/setup-java`) don't get the CA
  imported.
- **Throughput:** about 140–160 MiB/s per job through TLS interception, because the proxy is
  single-core.
- Linux (Ubuntu 24.04 / 26.04) GitHub-hosted runners only.
