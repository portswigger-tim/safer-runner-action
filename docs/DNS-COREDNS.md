# v2 DNS: CoreDNS, exact-FQDN allowlist (built)

Status: **built** on branch `v2` (after v2.0.0-beta.4). It replaces dnsmasq. The design was settled
by two spikes:
- `spike/dns-exact-fqdn-coredns` (`docs/DNS-exact-fqdn-coredns-spike.md`)
- `spike/dns-coredns-replace-vs-front` (`docs/spikes/dns-coredns/REPLACE-vs-FRONT.md`).

## What changed

| | before (beta.1–4) | now |
|---|---|---|
| resolver | dnsmasq (apt) | CoreDNS 1.15.0, upstream release tarball pinned by sha256 (`src/constants.ts`). It isn't in the Ubuntu 24.04/26.04 archives |
| allowlist semantics | a bare `x` = `x` + every subdomain (proxy and DNS) | a bare `x` = **exactly x**; `*.x` = subdomains; `.x` = both; `a*.x` = one-label glob |
| `<secret>.allowed.example` | forwarded upstream (a DNS exfil channel to the zone's name servers) | NXDOMAIN **on the runner**, never forwarded |
| DNS rebind drop | dnsmasq `stop-dns-rebind` (enforce; missed CGNAT on 2.91) | none at the DNS layer. The proxy's upstream-IP guard refuses a strict superset and logs the address |
| DNS log | dnsmasq request chains, A queries only | one self-labelled line per query: `ALLOW` / `BLOCK` / `WOULD_BLOCK`, every qtype |
| GitHub list | hand-written core list (suffix semantics) + static range | `api.github.com/meta` `.domains.actions`, live or the generated snapshot (`npm run gen:domains`), plus three justified exact `GITHUB_EXTRAS` |

## Pieces

- `src/config/corefile-builder.ts` is a pure function that turns patterns into a Corefile.
  - **enforce** has two server blocks.
    - The first block's `view` expression is allowed-and-not-denied: exact names go in one `name() in [...]`, `*.x` becomes `endsWith '.x.'`, and a glob becomes an anchored regex. It forwards with `cache 3600 { serve_stale 1h }`.
    - The second block is a catch-all `template ANY ANY { rcode NXDOMAIN }`. That makes the gate default-deny and fail-closed: a view that matches nothing denies, and a Corefile that doesn't parse means nothing listens on :53.
  - **analyze**: both blocks forward. The second block labels its queries `WOULD_BLOCK`.
  - The builder is checked against `proxy/test-vectors.json`, the same vectors as `compilePattern` (TS) and `compile_pattern` (Py). Names are restricted to `[a-z0-9_.-]`, so a quote or backslash can't inject into the expression.
- `src/dns.ts` handles install, Corefile, start and readiness.
  - The service runs via `systemd-run` as unit `safer-runner-dns`, as the random DNS uid, with `AmbientCapabilities=CAP_NET_BIND_SERVICE` and nothing else (`CapabilityBoundingSet` is the same). It uses `Restart=always`.
  - `StandardOutput=append:/var/log/safer-runner/dns.log` writes to a log that is pre-created root-owned with mode 0644.
  - CoreDNS starts **before** `resolv.conf` is switched to it, so there is no resolution gap. The firewall is unchanged: it is keyed on port 53 and the DNS uid.
- `/etc/hosts` names are answered locally by the `hosts` plugin, as dnsmasq did. This matters for containers, which resolve through Docker's embedded resolver, and for `dig`.
  - The names are routed into the allow block's view, and `hosts` (with `fallthrough`) answers them before `forward`.
  - They can't live in the deny block: in CoreDNS's fixed plugin order, `template` runs before `hosts`.
  - When `/etc/hosts` lacks the VM's own hostname (AWS-hosted runners), the address it resolved to before setup is added inline. Otherwise every `sudo` warns "unable to resolve host"; that happened under dnsmasq too.
  - These names are never forwarded. A subdomain of one is still refused.
- `src/parsers/dns-parser.ts` is about 20 lines.
- Self-test `dns-exact`: at setup, a random name under an exact entry must get `BLOCK` + NXDOMAIN in enforce, or `WOULD_BLOCK` in analyze.
- Report: a new **Subdomains of exact entries** section groups the refused names by their exact parent and suggests `add *.parent`.
- Every blocked name in the summary and job log goes through `src/redact.ts`: the subdomain section, the DNS-refused diagnostics, blocked SNI/Host rows, fronting SNIs and container rows.
  - Labels that look *encoded* (hex, base32/64) are shown as `‹N chars›`; the zone is always kept. Charset and length are the primary signal (vowel ratio, digit runs, hex), with Shannon entropy as a tie-breaker. The constants are tunable.
  - This complements GitHub's own masking, which only catches a secret's literal value. A refused lookup can carry data, and the public summary must not become the channel the resolver just closed.
  - Names that need redaction are never pasted into a suggested `allowed-domains` block.

## Accepted residuals

- **Wildcard entries are a DNS channel by design.** That applies to `*.github.com`, `*.githubapp.com` and `*.actions.githubusercontent.com` from meta, and to any `*.x` / `.x` a user adds.
- **No DNS-rebinding protection outside the proxy.** Every proxied flow is guarded by the proxy's IP check. A process that dials loopback, a docker bridge or IMDS:80 by name gets nothing it couldn't get by IP literal: those are exempt by design. The residual is browser-style rebinding of a local service inside the job, which is outside the egress threat model.
- The allowlisted apex itself is a tiny side channel: query type, 0x20 case variation, timing.

## Release note (draft)

> **Breaking: the allowlist is now exact by default, and DNS enforces it.** In beta.1–4 an
> `allowed-domains` entry such as `docker.io` also allowed every subdomain (`registry-1.docker.io`),
> and the DNS resolver forwarded any name under an allowlisted zone upstream. That meant
> `<secret>.allowed.example` could carry data to whoever runs the zone's name servers.
>
> From this release a bare entry means **that name only**. Use `*.example.com` for subdomains,
> or the new `.example.com` shorthand for the name and all of its subdomains, which matches the
> old behaviour. A lookup for a name under an exact entry is now answered NXDOMAIN on the runner
> and never leaves it. Wildcard entries remain a DNS channel to their zone by design.
>
> The resolver is now CoreDNS 1.15.0 (sha256-pinned) instead of dnsmasq. Setup no longer
> installs dnsmasq from apt. GitHub's own endpoints come from `api.github.com/meta`
> (`.domains.actions`) exactly as GitHub publishes them, live or from a generated snapshot.
>
> Internal-address answers (DNS rebinding) are now refused by the proxy alone. The proxy already
> covered a superset of them, and the job summary now shows the address. The summary also gains
> a **Subdomains of exact entries** section that suggests the `*.parent` entry to add, and
> encoded-looking labels in blocked names are redacted in the summary and job log.
>
> **To migrate:** run once in `mode: analyze` and add the suggested entries, or prefix entries
> whose subdomains you need with a dot (`.docker.io`).
