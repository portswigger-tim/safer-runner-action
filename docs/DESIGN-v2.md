# Safer Runner Action v2 — Design

**Status:** shipped in v2.0.0 (GA 2026-11-05); path and method filtering followed in v2.2.0 ·
**Author:** maintainers · **Supersedes:** v1 (stays supported in parallel)

> **How to read this note.** It is the design the action was built from, kept current where
> the code differs. Where the shipped code departs from the original plan, the text says so.
> The main differences:
> - DNS is **CoreDNS** with an exact-FQDN allowlist, not dnsmasq
>   ([DNS-COREDNS.md](DNS-COREDNS.md)).
> - The input set is final: `mode`, `allowed-domains`, `passthrough-domains`,
>   `block-risky-github-subdomains`, `dns-servers`, `disable-sudo`, `docker`,
>   `fail-on-tampering`, `http-filter`, `allow-github-platform` (§11).
> - Path and method policy shipped as `http-filter`
>   ([DESIGN-L7-path-method.md](DESIGN-L7-path-method.md)).
> - Container egress shipped as SNI-only for allowlisted names
>   ([DESIGN-v2-P2-containers.md](DESIGN-v2-P2-containers.md)).
> - The proxy ports are allocated at setup (a free pair in 20000-32766), not fixed at 8080.
> - The post-run report and tamper check are advisory
>   ([DESIGN-post-run-integrity.md](DESIGN-post-run-integrity.md)).

v2 moves the authoritative egress control from **L3/L4 (IP/ipset allowlisting)** to a
**L7 TLS-terminating egress proxy (mitmproxy)**, so policy is enforced on **hostname
(SNI/Host)** instead of IP. This closes the biggest structural gap in v1, where the
allowlist admits whole shared CDNs/clouds (S3, Fastly, Azure Storage, Cloudflare) and
`curl --resolve attacker-host:443:<allowed-ip>` reaches attacker co-tenants with a valid
cert.

This document is grounded in two pieces of work:
- the **v1 adversarial security review** (findings referenced as C1–C3, H1–H4, M1–M10), and
- the **v2 P0 mitmproxy spike** (proven on real `ubuntu-latest`/`24.04`/`26.04` runners).

> v1 is unchanged and keeps independent patches (`@v1`). v2 ships as a new major. It has no
> floating tag: users pin an exact version (`@v2.x.y`) or a commit SHA.

---

## 1. Goals / non-goals

**Goals**
- Enforce egress on **hostname**, not IP — close C3 (shared-CDN/cloud co-tenancy).
- Real L7 visibility: per-request host/path/method/bytes/verdict, not just DNS + IP:port.
- Keep the layered model: DNS (CoreDNS) and iptables become *supporting* layers; the proxy is the control.
- Work on GitHub-hosted `ubuntu-latest`/`24.04`/`26.04` (classic sudo + sudo-rs, iptables-nft).
- **Fail closed:** if the proxy is down, 80/443 egress is blocked, not open.

**Non-goals (v2.0)**
- Full request/response *content* policy. Path and method rules shipped later as `http-filter`
  (v2.2.0); body inspection is still out of scope.
- In-process / syscall-level attacks (container escape, kernel) — out of scope; defence in depth only.
- Protecting against an attacker who is already root on the runner *and* can keep root — see §12.
- Making every exotic client trust our CA automatically — best-effort, documented gaps.

---

## 2. Threat model

**Attacker:** code execution inside a job step — a compromised dependency, action, or build
script — which is the exact scenario the action exists to contain. Assume the attacker can
run arbitrary commands as the `runner` user, read the environment, and attempt arbitrary
network egress. Assume they **know safer-runner is present** and will try to bypass it.

**v2 defends (when combined with the privilege layer, see §12):**
- Egress to non-allowlisted hostnames over HTTP/HTTPS (the dominant exfil/C2 path).
- Hostname spoofing via `--resolve`, IP-literal connections, domain fronting (Host≠SNI).
- DNS tunnelling to arbitrary resolvers (all `:53` is forced through the local resolver; see §7).

**v2 does not defend (document honestly in the README, fixing v1's over-claims H3/M7):**
- Exfiltration *through* an allowlisted host (GitHub API, npm, etc.) — "GitHub itself is a
  full-capability channel" (M7). L7 Host enforcement narrows this but can't eliminate it.
- The job log / artifacts / caches as exfil channels.
- An attacker who gains and keeps root (can tear down the proxy and rules) — the integrity
  layer is a tripwire, not a control (H3).
- The post-run report and tamper check as evidence: the post step runs as the runner user from
  files the job's steps can modify, so they are advisory (see
  [DESIGN-post-run-integrity.md](DESIGN-post-run-integrity.md)).
- Cert-pinning clients and long-running pre-started agents that never trust our CA (§5).

---

## 3. Architecture overview

```
 job step (runner uid)                     safer-runner-proxy (systemd unit, outside runner tree)
   curl/git/node/pip/docker ──80/443──┐      ┌─────────────────────────────┐
                                       │      │  mitmdump --mode transparent │
 iptables nat OUTPUT REDIRECT ─────────┘ ───► │  policy.py (our addon):      │ ──► upstream
   (exempt: proxyUID, lo, IMDS, wire)         │   - own next_layer           │   (proxy-resolved
 iptables filter OUTPUT DROP non-redirected   │   - SNI allow @ ClientHello  │    SNI/Host; NOT the
   80/443 (fail-closed) + ip6 REJECT          │   - Host allow + Host==SNI   │    client-chosen IP)
                                              │   - repoint upstream         │
 CoreDNS (127.0.0.1:53) ◄── all :53 forced ──┘   - passthrough: hosted-compute-* only
                                                 - log every flow (host/verdict/bytes)
```

**Components**
1. **mitmproxy** (pinned version — the policy addon uses a private API) running headless
   (`mitmdump`), transparent mode, as a dedicated system user, under a systemd unit
   (`Restart=always`) **outside the runner's process tree** (orphan-process cleanup kills
   anything in-tree before "Complete job").
2. **Policy addon** (`policy.py`) — the heart of v2 (§4).
3. **iptables** force-through + fail-closed DROP + container PREROUTING DNAT (§7).
4. **Ephemeral CA** + trust injection across clients (§5).
5. **CoreDNS** — default-deny DNS resolution (exact-FQDN allowlist) + forcing all `:53`
   through us (defence in depth; the proxy, not DNS, is the authoritative control).
6. **Privilege layer** (sudo/docker) carried over from v1 (§12) — required for the proxy and
   rules to actually be a boundary.

---

## 4. Policy engine (the addon) — the part that must be exactly right

The spike proved a naive transparent proxy is **worse than v1**: by default mitmproxy
connects to *the IP the client chose*, so an attacker spoofs an allowed SNI and dials their
own IP. Three rules are mandatory.

### 4.1 Repoint every upstream (CRITICAL — else it's a bypass)
- The proxy must **resolve the SNI (TLS) or Host (HTTP) itself** and connect there, ignoring
  the client-chosen destination IP. Requires `connection_strategy=lazy`.
- Verified in the spike: without repoint, spoofing an allowed name to an attacker IP
  succeeded 9/9 (a working exfil channel for both TLS passthrough and plain HTTP). With
  repoint, the attacker IP was never reached, 9/9.
- Applies to **passthrough, plain HTTP, and the TCP connect of intercepted TLS**.

### 4.2 Own layer selection; enforce at both layers (defence in depth)
- Do **not** rely on mitmproxy's `ignore_hosts`/`allow_hosts` regexes — they also match the
  plaintext Host header and the destination `ip:port`, and the script `next_layer` hook runs
  *before* the built-in decider (in the spike this silently turned SNI enforcement off for a
  whole run). The addon owns layer selection.
- **TLS:** check SNI at the ClientHello; no allowlisted SNI → close, open no upstream.
- **HTTP (decrypted):** check `Host`; also enforce **Host == SNI** (block domain fronting;
  the spike got 403 on both host-not-allowed and host-sni-mismatch).
- **Block** no-SNI TLS and IP-literal TLS outright.
- Ship a **CI self-test** asserting an SNI-level block actually fired (not just the Host check).

### 4.3 Allow / passthrough / deny classes
- **deny** (default): not on the allowlist → blocked.
- **intercept-allow:** allowlisted → TLS-terminated, Host-checked, logged. The default for
  almost everything.
- **passthrough (SNI-only, no decrypt):** minimal, for hosts that *cannot* be MITM'd.
  - **Mandatory passthrough (empirical): `hosted-compute-*.githubapp.com` only.** The Go
    hosted-compute agent/watchdog load system roots at boot and can never trust a CA we add
    later; they run as **uid 1001 = the job steps' uid**, so UID exemption can't separate them.
  - Optionally the GitHub-owned `*.actions.githubusercontent.com` for resilience.
  - **Intercept** shared-tenant hosts (`productionresultssa*.blob.core.windows.net`, any
    CDN) — passthrough of them reopens a fronting-style C3 (SNI=allowed account, Host=another
    on the same front end). Only passthrough **single-tenant GitHub-owned** endpoints.
- Passthrough must still **repoint** (§4.1) and enforce the SNI allowlist.

### 4.4 Allowlist source
- Reuse v1's hardened approach: `api.github.com/meta .domains.actions` at runtime + static
  fallback, plus user `allowed-domains`.
- v2 enforces on **hostname**, so the meta wildcards (`*.github.com`, `*.githubapp.com`,
  `*.actions.githubusercontent.com`) map naturally to SNI suffix matches — and the
  shared-namespace `productionresultssa*` accounts are intercepted (not IP-allowlisted), so
  the exfil vector that drove v1's exact-list work is gone at L7. Keep the
  `DANGEROUS_BROAD_DOMAINS` *input* guard for user `allowed-domains` (M2).

---

## 5. CA & trust injection

An **ephemeral per-run CA** (generated at setup; mitmproxy mints JIT leaf certs per host).
Key lives in a `safer-runner-proxy`-owned `0600` confdir on tmpfs (root-readable), destroyed in post. This
is only a real boundary alongside `disable-sudo` (§12), same as the exempt proxy UID.

**Trust is not one store.** The spike confirmed clients diverge:

| Client | Trusts system store? | What's needed |
|---|---|---|
| curl / wget / git (system certs) | yes | `update-ca-certificates` |
| Python `urllib`/`ssl` | yes (system) | system store; `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` for requests/certifi (P1) |
| **Node (v22/v24)** | **no** | `NODE_EXTRA_CA_CERTS` **or** `NODE_USE_SYSTEM_CA=1` via `GITHUB_ENV` — **every JS action breaks without this** |
| .NET (the runner) | yes (re-reads OpenSSL) | works even if CA added after start |
| Go (hosted-compute agent) | loads roots once at boot | **cannot** trust a later CA → **passthrough** |
| Java / pip / Docker-in-container | varies | P1: keystore, `REQUESTS_CA_BUNDLE`, container CA mount |

### 5.1 Trust-injection sequence

1. Generate the ephemeral CA (or take mitmproxy's), write it to a root/proxy-user `0600`
   confdir (tmpfs).
2. **System store:** copy the CA (PEM) to `/usr/local/share/ca-certificates/safer-runner-ca.crt`
   and run `update-ca-certificates` → regenerates `/etc/ssl/certs/ca-certificates.crt`. Covers
   curl/wget/git/python-ssl/ruby/php/.NET.
3. **Env-var exports via `core.exportVariable` (`GITHUB_ENV`)** so every *subsequent* step
   inherits them:

   | Variable | Value | Covers |
   |---|---|---|
   | `NODE_EXTRA_CA_CERTS` | CA path | Node / all JS actions (checkout, upload-artifact, cache) |
   | `NODE_USE_SYSTEM_CA` | `1` | Node (belt-and-braces with the above) |
   | `REQUESTS_CA_BUNDLE` | bundle path | Python `requests` / certifi |
   | `PIP_CERT` | bundle path | pip |
   | `SSL_CERT_FILE` | bundle path | OpenSSL-env consumers that don't read the default path |
   | `GIT_SSL_CAINFO` | bundle path | git (when not using system certs) |
   | `AWS_CA_BUNDLE` | bundle path | AWS CLI/SDKs |
   | `CURL_CA_BUNDLE` | bundle path | curl (explicit) |

   `bundle path` = the regenerated `/etc/ssl/certs/ca-certificates.crt` (CA + system roots),
   so clients that read a single bundle still trust the public web too.

   **Java (not an env var — P1, verify on a runner):** on Debian/Ubuntu, if the
   `ca-certificates-java` package is installed, `update-ca-certificates` (step 2) runs its
   `jks-keystore` hook, which imports the system CAs into the *system* Java store
   `/etc/ssl/certs/java/cacerts` — so a JVM whose `$JAVA_HOME/lib/security/cacerts` is
   symlinked to that (the system OpenJDK default) is covered **for free**. BUT: (a) it's
   conditional on that package being present; (b) `actions/setup-java` and toolcache JDKs
   (Temurin/Zulu/Corretto) ship their **own** `cacerts` that is *not* symlinked and *not*
   touched — those need an explicit `keytool -importcert` into the active JDK's `cacerts`
   (or `-Djavax.net.ssl.trustStore`). Since most Java workflows pick a JDK via `setup-java`,
   plan to import into the active `$JAVA_HOME` as well, not rely on the hook alone. Java has
   no simple `*_CA_CERTS` env var. (Untested in the P0 spike.)

**Decision: set these unconditionally whenever the proxy is active** (both analyze and
enforce). Rationale: maximum compatibility with the fewest surprises; it is a *compatibility*
mechanism, not a security control (the containment is the force-through + proxy + privilege
layer), so there is no security downside to exporting them, and honest tools Just Work. The
exports must happen **early** — the action is designed to run first, and the pre-hook also
exports to `GITHUB_ENV` — so the vars reach the steps that need them.

**Cannot be retrofitted:** processes started *before* the action (notably the Go
hosted-compute agent, loaded at boot) will never trust a later CA. That's not solvable via
`GITHUB_ENV` and is another reason the passthrough set is minimal (§4.3).

---

## 6. Inspection depth

- **v2.0: hostname allowlist only** (SNI + Host), with **full request metadata logging**
  (method, host, path, status, bytes, verdict).
- **v2.2.0 added path and method policy** (`http-filter`, subtractive on allowed hosts), built on
  that logging: [DESIGN-L7-path-method.md](DESIGN-L7-path-method.md). Content (body) policy is
  not planned.

---

## 7. Forcing traffic through + fail-closed (iptables)

Proven setup from the spike (iptables-nft on 24.04 and 26.04, identical constructs):

1. **Start the proxy first** (systemd unit, `Restart=always`, outside runner tree).
2. `sysctl net.ipv4.conf.all.route_localnet=1`.
3. **nat OUTPUT → REDIRECT** tcp dports 80,443 → the proxy's loopback port (allocated at
   setup; the spike used 8080), **exempting**: the proxy UID, the resolver UID, `127/8`, IMDS
   `169.254.169.254`, wireserver `168.63.129.16`.
4. **`ss -K`** to kill pre-existing `:443` connections so the cutover is immediate and
   deterministic (REDIRECT only affects new conntrack flows; the runner has long-lived direct
   connections at setup time — they'd otherwise be DROPped and reconnect anyway).
5. **filter OUTPUT → REJECT** (shipped: in enforce the chain rejects everything except the
   proxy UID on 80/443, the resolver UID to its upstreams, `lo`, local bridges and the two
   Azure IPs) — this is the **fail-closed** guarantee: a hole in the REDIRECT is still stopped.
6. **ip6tables REJECT** 80/443 (no IPv6 proxy path; fixes v1's IPv6 gap, part of M3).
7. **Containers (C2):** `nat PREROUTING -i docker0/br-+ -p tcp --dports 80,443 -j DNAT
   --to 127.0.0.1:<container proxy port>` + `route_localnet`. Proven to block `docker run curl example.org`
   while allowing `api.github.com` **when the CA is mounted into the container** — CA
   injection into arbitrary images is the open P1 problem.

**DNS:** force all `:53` through the local resolver (CoreDNS; v1.4.0 loopback REDIRECT generalised) and **scope
the Azure platform allows** so `168.63.129.16:53` is *not* an open resolver (fixes C1/M4).
The proxy, not DNS, is now the authoritative egress control, but DNS stays for resolution +
logging and to stop DNS tunnelling.

**Interface/`eth0` assumption (M3):** detect the default-route interface at startup and
**fail closed (or warn loudly)** if egress isn't where we think; prefer "allow `lo` + the
proxy path, drop everything else" over `-o eth0`-scoped rules that fail open on a renamed/
extra NIC.

---

## 8. Performance & scaling

Spike data (~1 GB release asset, 18 jobs):

| Path | Single stream | 4 parallel | mitmdump CPU |
|---|---|---|---|
| Direct | ~232 MiB/s | ~655 MiB/s | — |
| **MITM** | ~164 MiB/s | **~164 MiB/s** (no gain) | **1 core pegged** |
| **Passthrough** (repointed) | ~238 MiB/s | ~577 MiB/s | ~0.9 core @ x4 |

- **MITM is single-core-bound** (one Python process). Parallel workloads (docker pulls,
  multi-file caches/artifacts) only get ~25% of direct throughput.
- **Strategy:** for big-download hosts (release-assets, blob caches, registries) use
  **repointed SNI passthrough** (≈ direct speed, still name-enforced) *where single-tenant*,
  or run **N mitmproxy workers** (iptables `statistic --mode nth` across ports). Keep the
  policy hook tiny.
- Always set `stream_large_bodies` (else whole bodies buffer in RAM; RSS ~170–225 MiB with it).
- Install/start is **20–55 s** today (107 MB tarball) — **cache or vendor** a pinned build.

---

## 9. Lifecycle, failure modes, observability

- **pre/main/post**, but per review H2 the **policy is applied in `pre`** (not just monitored)
  so later actions' pre-hooks are enforced, not merely logged; build the ruleset atomically
  and flush conntrack. Make the **strict privilege combo the documented default** (H1).
- **Proxy crash = fail-closed:** all 80/443 dead, including the agent, so the job can't report
  — `Restart=always` brings it back (measured in P1: a `SIGKILL`ed proxy restarts with the same
  CA and traffic recovers in about 2 s). An explicit `systemctl stop` needs root, which enforce
  removes.
- **Observability:** structured per-request log (host, verdict, bytes, SNI/Host, passthrough
  vs intercept) → a far richer job-summary report than v1's DNS+IP. Report counts with
  "+N more", show DENIED first and in full (fixes M6 truncation/`query[A]`-only gaps).

---

## 10. What v2 folds in from the review

| Finding | v2 handling |
|---|---|
| C3 shared-CDN co-tenancy | **Closed** by L7 SNI/Host enforcement + repoint. |
| C1 Azure DNS tunnel | Scope the `168.63.129.16`/IMDS allows to needed ports/UIDs; force `:53` through CoreDNS. |
| C2 container egress | PREROUTING DNAT (proven); CA-into-container is P1. |
| M1 custom DNS | Already fixed in v1.4.2; carry forward. |
| M3 `eth0`/IPv6 fail-open | Detect interface + fail closed; ip6tables REJECT. |
| M4 external direct-IP DNS | Forced through CoreDNS; `:53` not exempt for non-proxy UIDs. |
| H1/H2 defaults + pre-hook | Strict defaults; apply policy in pre. |
| H3 validation tripwire / M7 risky-subdomain theatre | Rewrite README expectations honestly; validation stays a tripwire, not a claim of "audit trail". |
| H4 supply chain | Org namespace, tag protection, immutable releases, dist reproducibility check — **pre-GA**. |

---

## 11. Inputs (as shipped)

The input surface in v2.2.x (see `action.yaml` and the README):
- `mode: analyze | enforce` (analyze = proxy logs, allows; enforce = allowlist enforced).
- `allowed-domains` (exact FQDN by default; `*.x`, `.x` and `a*.x` forms; keeps the
  dangerous-suffix guard).
- `passthrough-domains` (user-extendable; the mandatory set is always included).
- `block-risky-github-subdomains` (default `true`).
- `dns-servers` (upstreams for CoreDNS; default Quad9).
- `disable-sudo`, `docker` (`keep` | `remove-group` | `stop`), `fail-on-tampering`: mode-aware.
  Unset takes the enforce-safe value in enforce; an explicit value always wins. Enforce with
  sudo or docker kept is labelled ADVISORY.
- `http-filter`, `allow-github-platform` (path and method policy, v2.2.0).

The v1 inputs `sudo-config`, `disable-docker`, `stop-docker`, `primary-dns-server` and
`secondary-dns-server`, and the beta inputs `proxy-port`, `proxy-stream-large-bodies` and
`container-tls`, are gone. Migration table: [RELEASE-NOTES.md](RELEASE-NOTES.md) (v2.0.0). Proxy
tuning (worker count, large-download thresholds) was not built.

---

## 12. Security considerations / residual risks

- **The proxy + rules are only a boundary with the privilege layer.** The ephemeral CA key
  and the exempt proxy UID mean a step that can become root (or that UID) defeats everything.
  Removing sudo and docker access is therefore the enforce default (`disable-sudo`, `docker`),
  and privilege controls **fail closed** (M8): a docker removal that does not take fails setup
  in enforce.
- **Passthrough is a smaller but real hole** (SNI-only, no Host check). Keep it minimal and
  single-tenant.
- **Allowlisted hosts remain full-capability channels** (M7) — document, don't over-claim.
- **CA trust gaps** (pinned clients, pre-started agents) are passthrough or breakage; document.

---

## 13. Test plan

Real-runner matrix (separate test repo) on `ubuntu-latest`/`24.04`/`26.04`, per variant:
- **Must-pass:** allowed host (curl/git/node/python/docker), agent survival (checkout,
  upload/download-artifact, cache), container egress blocked for denied / allowed for allowed.
- **Must-fail (negative tests — the point of v2):** `--resolve` to a shared-CDN IP (C3),
  spoof-allowed-SNI-to-attacker-IP with repoint on (E/F), domain fronting (Host≠SNI), IP-literal
  TLS, no-SNI TLS, plain HTTP to attacker IP, a hole punched in REDIRECT (fail-closed DROP),
  IPv6 literal, Azure `168.63.129.16` DNS (C1), a pre-hook-planted sudoers drop-in (H2).
- **Self-tests:** assert an SNI-level block fired (not just Host); assert repoint (upstream IP
  ≠ client IP).
- **Perf regression:** single + parallel throughput, MITM vs passthrough.

---

## 14. Phased roadmap

- **P0 — Spike (DONE):** feasibility proven; three traps found (repoint, hook-order,
  Go-agent-passthrough); perf + passthrough set + container approach established.
- **P1 — Core product:** pinned mitmproxy + hardened `policy.py` (own `next_layer`, repoint,
  dual SNI/Host, passthrough classes, logging); CA trust matrix (system + Node + Python +
  Java/Docker); systemd supervision; iptables (force-through, fail-closed, DNS, interface
  detect, ip6); analyze/enforce; real-runner matrix with the negative tests + self-tests.
- **P2 — Containers (C2) + rich report + policy model** (hostname → allow/passthrough/deny;
  optional path/method logging→policy).
- **Status:** P0, P1 and P2 shipped in v2.0.0. Path/method policy shipped in v2.2.0. The P3 list
  below is the remaining wish-list, not a commitment; several items are covered
  ([LIMITATIONS.md](LIMITATIONS.md) lists what is still open).
- **P3 / GA gates:** proxy crash/restart mid-job; long jobs + watchdog via passthrough; OIDC
  (`token.actions`); service/container jobs; Azure blob Host-fronting under passthrough;
  IPv6 runners; larger runners (N workers); supply-chain hardening (H4); throughput strategy
  finalised; docs/Limitations rewritten honestly.

---

## 15. Open questions

Resolved at v2.0.0 unless marked open:

1. Worker model for throughput: **open.** One mitmproxy process; MITM is single-core bound
   (about 140-160 MiB/s). Passthrough remains the option for single-tenant big-download hosts.
2. CA injection into arbitrary container images (C2): **resolved.** Allowlisted names are
   checked by SNI only from containers, so no CA is needed there
   ([DESIGN-v2-P2-containers.md](DESIGN-v2-P2-containers.md)). A runtime shim to intercept
   inside containers is deferred.
3. Proxy-crash UX: **resolved.** `Restart=always` recovers in about 2 s; stopping the unit
   needs root, which enforce removes ([V2-P1-NOTES.md](V2-P1-NOTES.md), decision 16).
4. How much of the review (C1, M3, H1-H4) is v2-only vs. also back-ported to v1: **resolved.**
   v1 keeps independent security patches (`@v1`); v2 is a rewrite.
5. Analyze-mode behaviour: **resolved.** Analyze intercepts allowlisted hosts exactly as enforce
   does, and passes everything enforce would block through by SNI, logged `WOULD_BLOCK`
   ([V2-P1-NOTES.md](V2-P1-NOTES.md), decision 4).
