# Safer Runner Action — v2 (beta)

> **This is the `v2` branch: a beta of the next major version.** v1 (`@v1`, branch `main`)
> is unchanged and still supported. The v2 design is in [docs/DESIGN-v2.md](docs/DESIGN-v2.md);
> implementation decisions in [docs/V2-P1-NOTES.md](docs/V2-P1-NOTES.md).

Egress control for GitHub-hosted Ubuntu runners, enforced on **hostnames** rather than IP
addresses. All HTTP and HTTPS from the job is forced through a TLS-terminating proxy
(mitmproxy). The proxy checks the TLS SNI and every request's `Host` against an allowlist and
connects to the name itself, never to the IP the client chose.

v1 allowlisted IP addresses. That admits every tenant of a shared CDN or cloud range, so
`curl --resolve attacker.example:443:<allowed-ip>` reached an attacker-controlled site with a
valid certificate. v2 closes that.

## Usage

Put it **first** in the job. Its `pre` step applies the policy before any other step runs,
including other actions' `pre` steps.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: portswigger-tim/safer-runner-action@v2
        with:
          mode: enforce
          allowed-domains: |
            registry.npmjs.org
            pypi.org
            files.pythonhosted.org
          disable-docker: true    # docker access is root-equivalent (see "Limitations")
          # enforce removes sudo by default; `disable-sudo: false` keeps it but makes enforce ADVISORY
      - uses: actions/checkout@v5
      - run: npm ci
```

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

GitHub's own endpoints come from `api.github.com/meta` at runtime (with a static fallback),
so the runner, `actions/checkout`, artifacts and caches work without configuration.

## What enforce mode does

| Traffic | Result |
|---|---|
| HTTPS to an allowlisted name | TLS terminated with a per-run CA; each request's `Host` must equal the SNI |
| HTTPS to any other name, no SNI, or an IP literal | Closed at the ClientHello. No upstream connection is opened |
| `--resolve allowed.name:443:<any IP>` | The proxy connects to the real `allowed.name`; the client's IP is ignored |
| Domain fronting (`Host` ≠ SNI) | HTTP 403 |
| Plain HTTP | Decided by `Host`; the upstream is the `Host` name, never the client's IP |
| DNS to any server (`@8.8.8.8`, `@168.63.129.16`, ...) | Answered by the local dnsmasq. Only allowlisted names resolve |
| An allowlisted name that resolves to an internal address (IMDS `169.254.169.254`, loopback, RFC 1918, CGNAT `100.64/10`, IPv6 ULA / link-local) | Refused. dnsmasq drops such answers (`stop-dns-rebind`) and the proxy resolves every upstream once, refuses internal addresses and connects to the address it checked (no second lookup) |
| Any other TCP/UDP port, ICMP, IPv6 | Rejected |
| A hole in the redirect (proxy bypassed) | Still rejected by the filter (fail closed) |

Every job verifies two things on the live runner before any other step runs: an SNI-level
block actually fires, and the proxy ignores the client's chosen IP. In enforce mode the job
fails if either check fails.

## Inputs

| Input | Default | |
|---|---|---|
| `mode` | `analyze` | `analyze` or `enforce` |
| `allowed-domains` | | `example.com` = it and its subdomains; `*.example.com` = subdomains only; `a-*.example.com` = wildcard within one label. Shared namespaces such as `blob.core.windows.net` are refused |
| `passthrough-domains` | `hosted-compute-*.githubapp.com` | Hosts checked by SNI only (not decrypted). Use only for single-tenant hosts whose clients can't trust the CA. The default is always included |
| `block-risky-github-subdomains` | `true` | Deny `gist.github.com`, `gist.githubusercontent.com`, `raw.githubusercontent.com` |
| `primary-dns-server` / `secondary-dns-server` | Quad9 | Upstream resolvers for dnsmasq |
| `disable-sudo` | **on in `enforce`**, off in `analyze` | Remove the runner's sudo after setup. In enforce, `disable-sudo: false` keeps sudo and the job is labelled **ADVISORY** (see below) |
| `sudo-config` | | Custom sudoers rules for the runner user. Keeps sudo in enforce (labelled ADVISORY) unless `disable-sudo: true` is also set |
| `disable-docker` / `stop-docker` | `false` | Remove docker group membership or stop Docker |
| `fail-on-tampering` | `false` | Fail the job if the configuration changed during the job (the baseline is stored root-owned, `/etc/safer-runner/validation-state.json`) |
| `proxy-port` | `8080` | Loopback port of the proxy (advanced) |
| `proxy-stream-large-bodies` | `1m` | Stream rather than buffer bodies above this size (advanced) |

## CA trust

The per-run CA is added to the system store, so curl, wget, git, Python's `ssl`, .NET (the
runner itself) and Docker pulls trust it. The action also exports `NODE_EXTRA_CA_CERTS`,
`NODE_USE_SYSTEM_CA`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `SSL_CERT_FILE`, `GIT_SSL_CAINFO`,
`AWS_CA_BUNDLE` and `CURL_CA_BUNDLE` to later steps, and imports the CA into every JDK on the
image. The private key exists only on tmpfs, readable only by the proxy user, and the post
step deletes it.

## Enforce removes sudo by default (changed in v2.0.0-beta.2)

With sudo, any step can stop the proxy and flush the firewall, so enforce is only a boundary
without it. Since **v2.0.0-beta.2, `mode: enforce` removes the runner's sudo by default**
(`disable-sudo` unset = on). Only the action's own exact, read-only validation commands and
its post-step CA teardown stay allowed.

If a job needs sudo after the action, opt out explicitly with `disable-sudo: false` (or give
a `sudo-config`). The controls are still applied, but the job is **ADVISORY**: the run log
gets a warning and the job summary header reads *"enforce (ADVISORY — sudo retained, not an
enforced boundary)"*. In analyze mode, the summary tells you if the job used sudo, so you find
out before switching to enforce.

## Limitations (read these)

- **`disable-sudo: false` (or `sudo-config`) makes enforce advisory.** Any step with root can
  remove the proxy and firewall. **Docker group membership is root-equivalent too** and is
  still kept by default: set `disable-docker: true` or `stop-docker: true` in enforce unless
  the job needs docker. The summary warns when docker access was kept.
- **Allowlisted names that resolve to internal addresses are refused.** That includes hosted
  runners with Azure private networking that reach private services by name. Such names
  can't be allowlisted in enforce yet.
- **Allowlisted hosts are full-capability channels.** If `github.com` is allowed, a malicious
  step can push data to a repository it controls. v2 narrows egress to names; it can't judge
  what a request does.
- **Only TCP 80/443 is proxied.** In enforce, other ports are rejected, including SSH
  (`git@github.com`).
- **Containers are not filtered yet.** Traffic from containers goes through `FORWARD`, as in v1.
  Planned for v2 P2.
- **Clients that pin certificates, or that ignore both the system store and the variables
  above, fail** on allowlisted hosts. Fix: add the host to `passthrough-domains`, but only if it
  is single-tenant.
- **JDKs installed after this action** (for example by `actions/setup-java`) don't get the CA
  imported.
- **Throughput:** about 140–160 MiB/s per job through TLS interception, because the proxy is
  single-core.
- Linux (Ubuntu 24.04 / 26.04) GitHub-hosted runners only.
