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
          disable-sudo: true      # strongly recommended with enforce (see "Limitations")
          disable-docker: true
      - uses: actions/checkout@v5
      - run: npm ci
```

To work out what a job needs, start with `mode: analyze` (the default). Nothing is blocked.
The job summary lists every host the job contacted, marks the ones enforce mode would block,
and suggests an `allowed-domains` block.

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
| `disable-sudo` / `sudo-config` | `false` / | Remove or restrict the runner's sudo after setup |
| `disable-docker` / `stop-docker` | `false` | Remove docker group membership or stop Docker |
| `fail-on-tampering` | `false` | Fail the job if the configuration changed during the job |
| `proxy-port` | `8080` | Loopback port of the proxy (advanced) |
| `proxy-stream-large-bodies` | `1m` | Stream rather than buffer bodies above this size (advanced) |

## CA trust

The per-run CA is added to the system store, so curl, wget, git, Python's `ssl`, .NET (the
runner itself) and Docker pulls trust it. The action also exports `NODE_EXTRA_CA_CERTS`,
`NODE_USE_SYSTEM_CA`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `SSL_CERT_FILE`, `GIT_SSL_CAINFO`,
`AWS_CA_BUNDLE` and `CURL_CA_BUNDLE` to later steps, and imports the CA into every JDK on the
image. The private key exists only on tmpfs, readable only by the proxy user, and the post
step deletes it.

## Limitations (read these)

- **Without `disable-sudo`, enforce is advisory.** Any step with root can remove the proxy and
  firewall. The same goes for docker group membership.
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
