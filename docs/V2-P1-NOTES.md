# v2 P1 implementation notes

Decisions taken while building P1 where [DESIGN-v2.md](DESIGN-v2.md) was silent or left a
choice open. Each one is a default, not a final answer; revisit in P2/P3.

## Layout

| Path | What |
|---|---|
| `proxy/policy_core.py` | Pure hostname policy (no mitmproxy import): pattern matching, TLS and HTTP decisions, startup self-test. Unit-tested with plain Python. |
| `proxy/policy.py` | mitmproxy addon wiring the core in. Pinned to mitmproxy 12.3.1. |
| `proxy/test-vectors.json` | Matching vectors checked by **both** the Python and the jest tests. |
| `src/egress.ts` | Setup orchestration (runs in `pre`; `main` only if `pre` didn't complete). |
| `src/policy.ts` | Builds `policy.json`; TS mirror of the matcher for the report and dnsmasq. |
| `src/proxy.ts` | mitmdump install (sha256-pinned), proxy user, ephemeral CA, systemd unit. |
| `src/trust.ts` | System store, `GITHUB_ENV` CA variables, Java keystores. |
| `src/firewall.ts` | iptables / ip6tables rulesets (pure generators + atomic apply). |
| `src/selftest.ts` | Live self-tests on every job (SNI-layer block fired; repoint). |
| `src/report.ts`, `src/post.ts` | L7 job summary; CA key teardown. |

## Decisions

1. **The addon owns layer selection completely.** Instead of calling the built-in
   `NextLayer._next_layer()` (the spike's private-API approach), the addon neutralises the
   built-in hook at load and decides every layer itself: TLS (by ClientHello) or HTTP, and
   only HTTP inside intercepted TLS. An undecided connection (split ClientHello) waits for
   more data; nothing else can decide for it. A startup check refuses to run if the built-in
   is still active, `connection_strategy` isn't `lazy`, or the mitmproxy version differs.
2. **Fail closed in the addon.** Every hook catches exceptions and blocks. Startup errors make
   mitmdump exit (mitmproxy's ErrorCheck), so a broken policy never runs as an open proxy;
   systemd restarts it, the REDIRECT then hits a closed port.
3. **Repoint in `requestheaders`** by setting `request.host` to the SNI (HTTPS) or Host (HTTP):
   mitmproxy picks the upstream from `(request.host, request.port)` after that hook. The
   port is always the one the client dialled (80/443).
4. **Analyze mode = enforce for allowlisted hosts, SNI passthrough for the rest.** Allowlisted
   hosts are intercepted exactly as in enforce (so analyze surfaces CA-trust problems you'd hit
   in enforce); anything enforce would block is logged `WOULD_BLOCK` and passed through by SNI
   (repointed), so analyze never breaks a client that doesn't trust our CA. (Design open
   question 5.)
5. **Own CA instead of mitmproxy's default:** RSA-2048, 3-day validity, `CN=safer-runner
   ephemeral CA <run id>`, generated as the proxy user with umask 077 on tmpfs
   (`/run/safer-runner/proxy`).
6. **CA teardown keeps the proxy running.** `post` deletes the key from disk through a
   root-owned helper (`/opt/safer-runner/bin/teardown`, the only extra sudoers entry with
   `disable-sudo`). The proxy keeps the CA in memory: the runner's own "Complete job" traffic
   still has to go through it, and the VM is destroyed afterwards. Consequence: a proxy crash
   *after* post would come back with a new CA (fail closed, not open).
7. **The addon is copied to a root-owned directory** (`/opt/safer-runner/proxy`) because the
   action checkout is writable by the runner user, and `Restart=always` re-reads the script.
8. **Only TCP 80/443 is proxied.** In enforce every other port (incl. SSH git, DoT, custom
   ports) is rejected; in analyze it's allowed and logged. QUIC (UDP/443) is rejected in both
   modes so HTTP/3 clients fall back to TCP through the proxy.
9. **All DNS (any destination) is REDIRECTed to dnsmasq**, generalising v1.4.0's loopback rule:
   `dig @8.8.8.8` / `@168.63.129.16` / `@127.0.0.100` are answered by our dnsmasq (filtered in
   enforce, logged in both). The wireserver allow is scoped to tcp/80,32526.
10. **Firewall is interface-agnostic** (allow lo, local docker bridges, the proxy uid on 80/443,
    dnsmasq's uid to its upstreams, the two Azure endpoints; reject the rest). Rejects (RST /
    port-unreachable) rather than silent drops so tools fail fast. The default-route interface
    is detected and warned on, but correctness doesn't depend on it.
11. **Host→docker bridge traffic is not redirected/blocked** (service containers keep working);
    container egress via FORWARD is still unfiltered — C2 is P2, unchanged from v1.
12. **`passthrough-domains` is additive.** The mandatory `hosted-compute-*.githubapp.com` is
    always included even if the input is overridden (removing it breaks the job).
13. **No query strings in logs.** The flow log and report record the path only: query strings
    carry SAS tokens (artifact/cache URLs) and the job summary is visible to repo readers.
14. **Proxy port stays 8080 (design default) but is an input.** 127.0.0.1:8080 collides with a
    job that binds 0.0.0.0:8080 — consider a less common default before GA.
15. **mitmproxy "vendoring" = sha256-pinned download** of the official tarball (only `mitmdump`
    is extracted), done in parallel with the dnsmasq install. See timings in the P1 report;
    an Actions-cache layer can be added if the CDN is slow.
16. **~~Strict privilege defaults are documented, not forced.~~ Superseded in
    v2.0.0-beta.2 (review H2): enforce removes sudo by default.** `disable-sudo` is tri-state.
    If it is unset, it is **on in enforce** and off in analyze. An explicit `true`/`false`
    always wins. A non-empty `sudo-config` keeps sudo unless `disable-sudo: true` is also set.
    action.yaml has no default for it, so "unset" and "false" stay distinguishable
    (`resolveDisableSudo`). Enforce with sudo kept (`disable-sudo: false` or `sudo-config`)
    runs as **ADVISORY**. The run log gets a titled warning, and the job-summary header reads
    "enforce (ADVISORY — sudo retained, not an enforced boundary)" with a WARNING callout. In
    analyze mode, the summary says if the job used sudo. **Behaviour change:** a
    default-enforce job that runs `sudo` after the action now fails. It must set
    `disable-sudo: false` (advisory) or drop the sudo use. The action's own post step (CA
    teardown and validation reads) uses only exact sudoers entries and works either way.
    Docker group access is still kept by default and is also root-equivalent. Enforce warns
    about it in the log and the summary (CAUTION), but it is not flipped.
    *Proxy unit:* the proxy is a transient `systemd-run` unit with `Restart=always`. `Restart=`
    only covers the process exiting. An explicit `systemctl stop` (root only) stops it for good:
    the transient unit is then garbage-collected, and egress fails closed (REDIRECT to a closed
    port) until someone with root also flushes the rules. A non-transient unit or a watchdog
    would not change that, because root can stop or mask either. What closes it is removing
    root, which is now the enforce default. The runner user can't stop the unit (polkit) or
    signal the process (different uid). The real-runner harness checks both.

17. **Allow `-d 127.0.0.0/8` in the filter chain.** Found on the first real-runner run: after a
    nat OUTPUT `REDIRECT`, filter OUTPUT still sees the *original* output interface (`OUT=eth0`,
    `DST=127.0.0.1`), so `-o lo` never matches proxied packets. A default-deny chain then
    rejects everything going through the proxy, including the runner agent's own traffic (the
    job hangs and can't be cancelled). The spike didn't hit this because it only dropped
    dport 80/443.
18. **The enforce reject log records new connections only.** Packets from connections that
    predate the cutover, and ownerless RST/FIN from sockets closed by `ss -K`, are still rejected
    but no longer fill the report.

19. **Upstream IP guard (review H1).** Repoint fixed *which name* the proxy connects to, but not
    *which address* that name resolves to. An allowlisted name an attacker can point at
    `169.254.169.254`, `127.0.0.1` or RFC 1918 space was an SSRF route through the proxy (the
    proxy uid may reach any IP on 80/443). There are now two layers:
    - **dnsmasq** (enforce only): `stop-dns-rebind`, with no `rebind-*-ok` exemptions. It drops
      upstream answers in loopback, RFC 1918, link-local (IMDS) and ULA space. The Azure IMDS
      and wireserver are reached by IP (firewall exemptions), never by name, so they are
      unaffected.
    - **addon** (`server_connect` hook, the one place every upstream connection goes through:
      intercept, passthrough and plain HTTP): the name is resolved **once**. The connection
      is refused if *any* resolved address is in `FORBIDDEN_UPSTREAM_NETS` (loopback,
      link-local, RFC 1918, CGNAT `100.64/10` — which dnsmasq does not cover — the
      wireserver, multicast/reserved, `::1`, `fe80::/10`, `fc00::/7`, IPv4-mapped forms). Otherwise
      the connection is **pinned** to the checked IPv4 address (IPv4 preferred: there is no
      IPv6 egress path, L2), so mitmproxy cannot re-resolve (no TOCTOU/rebind). The name is put
      back on the connection after connect (bypassing `Server.__setattr__`), because mitmproxy
      matches reusable connections by address. Enforce: `BLOCK`, the client gets a 502/close,
      and the flow log has an `ev=upstream` record with reason `upstream-ip-forbidden` /
      `upstream-unresolved`. Analyze: `WOULD_BLOCK` and the connection goes ahead (analyze is
      monitoring only).
    - Caveat: GitHub-hosted runners with Azure private networking, which reach private
      services by name, can't use those names in enforce. There is no exemption input yet.

20. **The fail-on-tampering baseline is root-owned (review M1).** It used to be
    `/tmp/safer-runner-validation-state.json`, written and read by the runner user, so a step
    could rewrite it to match a tampered state. It is now
    `/etc/safer-runner/validation-state.json`, `root:root 0600`, with mode and owner set before
    the content is written. Post reads it with `sudo -n cat <exact path>`, an exact entry in
    the validation sudoers allowlist, so it works with `disable-sudo`. If the baseline is
    missing or unreadable, the job is reported as not intact.

## Measured on GitHub-hosted runners (P1)

- Setup in `pre`: about 20 s. The dnsmasq apt install is about 10 s and runs in parallel with
  the mitmdump download (about 2 s) and extract (0.3 s). Proxy start is about 1 s. CA trust,
  including Java, is about 2.5 s. DNS and firewall together take under 2 s, and the live
  self-tests take 0.2 s.
- Interception throughput: about 142 MiB/s for a single 300 MiB stream.
- Proxy `SIGKILL`: systemd restarts it with the same CA from tmpfs, and traffic recovers in
  about 2 s.
- dockerd started at boot does trust the CA added later. `docker pull` works through the
  interception when the registry and blob hosts are allowlisted.
- Java: the keytool import covers the image's Temurin JDKs. On 26.04 `cacerts` resolves to
  `/etc/ssl/certs/adoptium/cacerts`.

## Deferred (P2/P3)

- Container egress (C2): PREROUTING DNAT + CA into images.
- N proxy workers for throughput (MITM is single-core bound, ~160 MiB/s).
- Byte counts for passthrough connections.
- JDKs installed after the action (e.g. `actions/setup-java`) don't trust the CA.
- Proxy crash/restart mid-job, long jobs, OIDC, service containers, IPv6 runners, larger runners.
