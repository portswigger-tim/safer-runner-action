# Safer Runner Action v2 — P2: container egress (C2)

> **Status: BUILT on `v2` (P2 build session, 2026-11-05)** — see "Build outcome" below; the
> rest of this document is the spike + design it was built from.
>
> **Build outcome (deviations from the plan, all measured on runners):**
> - **Source classification = second listener, proven.** mitmproxy runs
>   `--mode transparent@127.0.0.1:<P> --mode transparent@127.0.0.1:<P+1>`; containers are
>   DNATed to `P+1`. Classify by `client.proxy_mode.custom_listen_port` — **not**
>   `client.sockname`, which in transparent mode is the connection's *original destination*
>   (e.g. `140.82.114.4:443`), not the listener. All `172.x` clients were `container`, all
>   VM-eth0 clients `host`. The local-address fallback was not needed.
> - **Ports are allocated at setup** (free consecutive pair in 20000–32766, below the ephemeral
>   range) unless `proxy-port` is set; `8080` is no longer the default.
> - **`conntrack` is not on the hosted images**: it is now apt-installed with dnsmasq (the spike's
>   `conntrack -D` silently never ran).
> - **Posture C is the only implemented posture.** `container-tls: intercept` is accepted and
>   treated as `sni-only` with a warning (runtime shim deferred to P3).
> - **Front doors:** the Azure Storage family (`*.{blob,dfs,file,queue,table,web}.core.windows.net`)
>   stays intercepted for containers in **enforce**; in analyze it is SNI-only (analyze never
>   breaks containers). Constant in `proxy/policy_core.py` + `src/policy.ts`, pinned by
>   `proxy/test-vectors.json`.
> - **F1** restarts dockerd when docker runs and is retained *or* containers are running
>   (1–7 s measured; service containers kept); `daemon.json` joins the baseline.
>
> Original status: **spike + design, NOT built.** Everything here was run on GitHub-hosted runners
> (`ubuntu-latest`, `ubuntu-24.04`, `ubuntu-26.04`) on top of `v2.0.0-beta.3`, with the
> container rules and CA-injection candidates added by spike scripts. Nothing has been
> merged into `v2`. The evidence and the harness are listed in §11.
>
> Parent design: [DESIGN-v2.md](DESIGN-v2.md) (§7 item 7, §5, §14 P2, §15 Q2).
> Build notes for the host path: [V2-P1-NOTES.md](V2-P1-NOTES.md).

## 0. TL;DR

- **Traffic + fail-closed: proven, ready to build.** `nat PREROUTING -i docker0/br-+` DNAT
  of 80/443 to the proxy and of :53 to dnsmasq, plus a `DOCKER-USER` chain that REJECTs anything
  else a container forwards off-host. Denied names are blocked at DNS *and* at the proxy (SNI and
  Host). Allowlisted names work. Non-80/443 ports, IP literals and IMDS are refused. If 443 is
  removed from the DNAT, `DOCKER-USER` still REJECTs it. Container↔container and container→host
  traffic is not hijacked. The rules survive a `dockerd` restart. This held on all three OSes,
  Docker 28.0.4 and 29.4.2.
- **Container DNS: proven, needs no daemon.json.** The default bridge (`8.8.8.8` in the
  container) is caught by the :53 DNAT. Docker's embedded resolver (`127.0.0.11`, user networks
  and service containers) forwards from the **host** netns to our dnsmasq, so it is already caught
  by the v2 OUTPUT :53 REDIRECT. A raw UDP query to `8.8.8.8` from a container is answered by our
  dnsmasq (NXDOMAIN) and logged.
- **Today (beta.3) the gap is real, including under default enforce.** Service containers
  (started by the runner *before* the action) keep running after docker is removed. They have
  unfiltered IP egress: `tcp 1.1.1.1:853` connects and `github.com` is reached directly, not
  through the proxy. Any `docker run` container reaches `https://example.org` and the Azure IMDS
  (`200`).
- **CA trust into containers is a per-image property: no single mechanism covers everything.**
  - Bind-mounting the host bundle covers OpenSSL/Go-style clients (curl on Debian and UBI,
    Python `ssl` on Debian, Alpine and distroless).
  - It does **not** cover Node (bundled Mozilla store), Java (its own `cacerts`), Python
    `requests` (certifi), or images that point a CA env var at their own file
    (`curlimages/curl` → `/cacert.pem`).
  - Env vars + mounts cover all 10 images tested.
  - The action does not control the user's `docker run`. The one mechanism that does reach it is
    a **default OCI runtime shim** (`daemon.json` `default-runtime`, loaded with SIGHUP, no
    restart). It made all 10 images trust the CA with no change to their command line.
  - The shim does **not** reach service containers, the job `container:` (both are created
    before the action), `docker build` RUN steps (BuildKit's own executor), or `--runtime runc`.
- **Posture recommendation: SNI-only for container sources by default; intercept + runtime shim
  as an opt-in** (§6). SNI-only was prototyped in the addon and works for every image with **no
  CA**. Denied names are still blocked, and the upstream is still repointed to the proxy-resolved
  name. The cost is the loss of the Host check for container traffic: domain fronting within a
  front-end that serves the allowlisted SNI becomes possible. Today's default (intercept, no CA)
  is fail-closed but breaks every container that speaks HTTPS to an allowlisted host. Analyze
  mode breaks them too, which contradicts "analyze never breaks".
- **Four findings outside the C2 scope that the build session or the human need to act on (§2).**
  - **F1, a beta.3 bug:** `dockerd` won't trust the CA if it did TLS before the action ran. Any
    job with a service container hits this, and every later `docker pull` of an intercepted
    registry fails with x509 errors in **every** mode, including analyze.
  - **F2:** default enforce breaks `uses: docker://` / Dockerfile actions.
  - **F3:** a job `container:` makes the action fail.
  - **F4:** `ubuntu-latest` sometimes lands on **AWS**.
- **Verdict:** P2 is ready for a build session for traffic, DNS, fail-closed, the F1 fix and the
  SNI-only container posture. The intercept + runtime-shim opt-in can be built in the same
  session, or deferred to P3 if the human picks SNI-only as the only mode. One more short
  confirmation round is needed for the dual-listener source classification (§3.3), which is a
  design choice and has not been run yet.

---

## 1. What was proven (real runners)

Runs on `portswigger-tim/safer-runner-action-test` branch `spike/v2-containers`, workflow
`p2.yml`. The action is `v2.0.0-beta.3` (runs 1–2) or the action branch `spike/v2-containers` =
`v2` head + the posture switch (runs 3–4). Results are identical across `ubuntu-latest`,
`ubuntu-24.04` and `ubuntu-26.04` unless stated. Docker 28.0.4 runs on latest/24.04 and Docker
29.4.2 on 26.04. runc is 1.5.2 and iptables 1.8.10/1.8.11 (nf_tables).

| # | Check (container on docker0 / user bridge unless stated) | beta.3 today | with P2 rules |
|---|---|---|---|
| G1 | `curl https://example.org` | **200 (gap)** | refused: NXDOMAIN (DNS) and, forced to an IP, proxy `BLOCK sni-not-allowed` (client `172.17.0.2`) |
| G2 | `tcp 1.1.1.1:853` | **open (gap)** | REJECT (`DOCKER-USER` → `SR_CFWD`) |
| G3 | Azure IMDS `169.254.169.254:80` | **200 (gap)** | 403 (proxy: IP-literal Host) |
| G4 | service container (started pre-action), default enforce: TCP to 1.1.1.1:853 / HTTPS github.com without CA | **connected / 200 direct (gap)** | REJECT / TLS fails (intercepted, no CA) |
| T1 | allowlisted `https://github.com` with CA | n/a | 200, proxy `ALLOW` record with container client IP, repointed |
| T2 | `http://example.org` (forced to 1.1.1.1) | n/a | 403, proxy `BLOCK host-not-allowed` |
| T3 | `https://1.1.1.1` (IP literal) | n/a | refused |
| T4 | **fail-closed:** 443 removed from the DNAT, `https://1.1.1.1` | n/a | refused by `SR_CFWD` (reject counter increments) |
| T5 | container → nginx container on the same user network :80 | 200 | **200** (not hijacked) |
| T6 | container → host `172.17.0.1:80` / `host.docker.internal:80` | 200 | **200** (not hijacked) |
| T7 | `--network host` container | n/a | host path (OUTPUT REDIRECT): proxy `BLOCK`; client = VM eth0 address |
| T8 | rules after `systemctl restart docker` | n/a | our `PREROUTING` + `DOCKER-USER` jumps intact, still ahead of Docker's; still blocking |
| N1 | DNS, default bridge (`resolv.conf` = `8.8.8.8 8.8.4.4`, Docker's fallback because the host has `127.0.0.1`) | unfiltered | denied → NXDOMAIN, allowed resolves; query seen in **our** dnsmasq log |
| N2 | DNS, user network (`127.0.0.11`) | partly (see §4) | same as N1 |
| N3 | raw UDP DNS query to `8.8.8.8` (tunnel test) | unfiltered | answered by our dnsmasq (`rcode 3`), logged from `172.17.0.2` |
| B1 | `docker build` RUN (embedded BuildKit and `buildx` docker-container driver) | unfiltered | DNS filtered (denied → `Could not resolve host`), allowlisted HTTPS intercepted → `curl: (60)` (no CA in the build); **200 under posture C (SNI-only)**, with no CA |
| P1 | posture C (spike addon): container, **no CA**, allowlisted host: node / java / curl-alpine / requests | n/a | 200 for all four; proxy `PASSTHROUGH reason=container-sni-only source=container`, repointed |
| P2 | posture C: container, no CA, `example.org` forced to 1.1.1.1 | n/a | refused, proxy `BLOCK sni-not-allowed` |
| P3 | posture C on: host `curl github.com` | n/a | still `INTERCEPT` (client = VM eth0 address, correctly classified as host after the run-4 fix) |

## 2. Findings beyond C2 (act on these)

**F1 — `dockerd` stops trusting the per-run CA when it did TLS before the action (beta.3
bug).** `dockerd` is Go and loads the system roots once, on first use. If the runner pulled a
service-container (or job-container) image before the action, which is always the case when
`services:` or `container:` is set, the roots are cached without our CA. Every later
`docker pull` from an intercepted (allowlisted) registry then fails with
`x509: certificate signed by unknown authority`.
- This was hit in **enforce, advisory and analyze** (analyze intercepts allowlisted hosts too).
- P1's "dockerd trusts the runtime CA" was measured without services, so it didn't hit this.
- `/etc/docker/certs.d/<registry>/ca.crt` did **not** help.
- **Fix (proven):** set `live-restore: true` in `daemon.json`, `SIGHUP` dockerd (live-restore
  is reloadable), then `systemctl restart docker`. It takes 1–3 s; running service containers
  survive (same container IDs, health checks continue); pulls work afterwards. Do this
  **before** applying the firewall.

**F2 — default enforce (beta.3, docker removed) breaks Docker container actions.** The runner
agent runs as the `runner` user, so `disable-docker` removes docker from the runner itself:
- `uses: docker://alpine` failed with `permission denied ... docker.sock`.
- The runner's end-of-job cleanup of service containers and networks also fails. It's only a
  warning, so the job still passes.

Service containers keep running, unfiltered (G4). This is the beta.3 default, not P2, but P2
has to document it, and the human may want an escape hatch. Docker actions are incompatible with
`disable-docker`, so the summary should say so.

**F3 — job `container:` is unsupported.** JS actions run *inside* the job container (as root,
with `/var/run/docker.sock` mounted). There the action fails at once:
`Unable to locate executable file: sudo`. In enforce the step fails, which is good. With
`continue-on-error` the job runs fully unprotected: `example.org` was reached. The action can't
apply host iptables from inside the container in any supported way. Recommendation: detect it
(`/.dockerenv` / cgroup / `GITHUB_ACTIONS` + no sudo) and fail with a clear message in enforce,
warn in analyze, and document "use `services:` + `docker run` steps instead". *(Escaping to the
host through the mounted socket would be possible, but it's a hack and out of scope.)*

**F4 — `ubuntu-latest` sometimes runs on AWS, not Azure.** Seen in runs 2–3:
- `search us-west-2.compute.internal`, resolver `10.0.0.2`;
- IMDS answered `401` (IMDSv2) where Azure answers `200`.

The v2 firewall's Azure constants (`168.63.129.16`, IMDS on :80) are harmless there, but any
"we're on Azure" assumption should be revisited (not P2 scope).

**F5 — the source of host traffic at the proxy is the VM's eth0 address, not 127.0.0.1.** nat
OUTPUT REDIRECT keeps the original source, so the proxy sees `client=10.1.0.x` for host traffic.
That's also a private address. A "private source ⇒ container" rule misclassifies the host: the
spike did exactly that in run 3 and was fixed in run 4. §3.3 picks a robust classifier.

## 3. Recommended traffic design (production constructs)

### 3.1 Rules (new generators in `src/firewall.ts`, applied with the existing atomic `iptables-restore --noflush`)

```
*nat
:SAFER_RUNNER_CNAT - [0:0]
-A SAFER_RUNNER_CNAT -m addrtype --dst-type LOCAL -j RETURN              # container -> host services
-A SAFER_RUNNER_CNAT -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j RETURN # container <-> container (br_netfilter)
-A SAFER_RUNNER_CNAT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:53
-A SAFER_RUNNER_CNAT -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:53
-A SAFER_RUNNER_CNAT -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 127.0.0.1:<container-port>
-I PREROUTING 1 -i docker0 -j SAFER_RUNNER_CNAT
-I PREROUTING 1 -i br-+   -j SAFER_RUNNER_CNAT
COMMIT
*filter
:SAFER_RUNNER_CFWD - [0:0]
-A SAFER_RUNNER_CFWD -o docker0 -j RETURN
-A SAFER_RUNNER_CFWD -o br-+ -j RETURN
-A SAFER_RUNNER_CFWD -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# enforce:
-A SAFER_RUNNER_CFWD -m conntrack --ctstate NEW -m limit --limit 60/min -j LOG --log-prefix "SaferRunner-CDrop: "
-A SAFER_RUNNER_CFWD -p tcp -j REJECT --reject-with tcp-reset
-A SAFER_RUNNER_CFWD -j REJECT --reject-with icmp-port-unreachable
# analyze: LOG "SaferRunner-CEgress: " and RETURN
-I DOCKER-USER 1 -i docker0 -j SAFER_RUNNER_CFWD
-I DOCKER-USER 1 -i br-+   -j SAFER_RUNNER_CFWD
COMMIT
```
plus `sysctl net.ipv4.conf.all.route_localnet=1` (already set by v2) and, after applying,
`conntrack -D` for flows sourced from the Docker subnets. Without that, a service container's
pre-existing connections continue via `ESTABLISHED`. This is the forwarded-traffic counterpart
of v2's `ss -K`.

Notes, all observed:
- **Why the RFC1918 exclusion.** Docker loads `br_netfilter` (the
  `bridge-nf-call-iptables` sysctl wasn't visible from the job, but bridged traffic did traverse
  PREROUTING). Without the exclusion, container→container `:80` would be hijacked to the proxy
  and refused. Excluded private destinations fall through to `SR_CFWD`: same bridge → allowed,
  anything off-host → REJECT. So container egress to a private off-host address (VNet, AWS
  `10.0.0.2`) is refused in enforce, which is consistent with the proxy's upstream IP guard.
- **Why `addrtype LOCAL`.** Container → host services (`172.17.0.1:80`,
  `host.docker.internal`) must keep working, and Docker's own published-port `DOCKER` chain sits
  behind it.
- **`DOCKER-USER`, not our own FORWARD position.** Docker re-inserts its FORWARD jumps on every
  restart, ahead of ours. `DOCKER-USER` is the chain Docker promises to leave alone. Run 3
  confirmed the jumps and contents survive `systemctl restart docker`. If Docker is not running
  at setup (`stop-docker`), skip the container rules; Docker can't start without root anyway.
  If Docker is running but `DOCKER-USER` is missing (Docker's iptables integration off, or a
  non-iptables backend), enforce fails setup before any rule is applied; analyze warns and
  applies only the host rules. The setup marker's `containerRules` records what was applied.
- **IPv6:** container IPv6 is off by default (no `--ipv6` networks were tested). Mirror the
  `DOCKER-USER` REJECT in ip6tables so an IPv6-enabled user network fails closed. *Not run on a
  runner; cheap to add.*
- **Analyze:** the same DNAT (for visibility), `SR_CFWD` logs and allows. Note: the existing
  rsyslog filter didn't pick up the `CEgress` prefix in the spike, so the build must add the new
  prefixes to `setupIptablesLogging`.

### 3.2 Proxy listener

The spike reused the host listener (127.0.0.1:8080). mitmproxy's transparent mode reads the
DNAT original destination exactly as it does for REDIRECT, so the proxy needed no change to
**accept forwarded connections**.

### 3.3 Classifying container vs host sources (needed for any per-source posture)

- **Spike (proven, run 4):** container = private source address that is **not** a host-local
  address (read from `/proc/net/fib_trie` at addon load). It works, but depends on the address
  plan, and the local-address set can go stale.
- **Recommended for the build:** DNAT container traffic to a **second transparent listener**
  (e.g. `127.0.0.1:<proxy-port+1>`). The addon then classifies by the listener the connection
  arrived on (`client.sockname` port), with no source-IP inference, and `--network host`
  containers are correctly "host". This needs mitmproxy 12's multiple `--mode transparent@port`
  listeners, which have **not been run on a runner yet**. It's the first thing the build session
  should prove (§9 step 2). If it doesn't work, fall back to the local-address rule.

## 4. Container DNS

What we saw:
- **Default bridge:** Docker writes `nameserver 8.8.8.8 / 8.8.4.4` because the host's
  `resolv.conf` is `127.0.0.1` after v2 setup. Those queries leave via docker0 and are DNAT'd to
  dnsmasq. Proven: the denied name gets NXDOMAIN and appears in the dnsmasq log with client
  `172.17.0.2`.
- **User networks and service containers (`127.0.0.11`):** Docker's embedded resolver forwards
  external queries from the **host** network namespace (they appear in dnsmasq as `127.0.0.1`).
  That makes them already subject to v2's OUTPUT `:53` REDIRECT, and they're filtered even
  without P2 rules. **Caveat:** in run 1 (no dockerd restart), the service container resolved
  `example.org` *before* our rules. Its resolver config had been captured when the container was
  created, before the action (host upstream `168.63.129.16`), and those queries took the
  container/FORWARD path. After the rules they were filtered. The DNAT plus `DOCKER-USER` REJECT
  covers both paths, so DNS is enforced whatever Docker decides.
- **dnsmasq needs no change:** it's bound to `127.0.0.1` (`bind-interfaces`) and answers DNAT'd
  queries arriving on docker0/br-*.
- **No `daemon.json` `dns` setting is needed.** That would require a restart and would only
  cover the default bridge anyway. The DNAT is authoritative.
- **DNS tunnelling** from containers goes through dnsmasq's enforce filtering, the same as the
  host. There's no direct resolver path: `:53` to anything else is DNAT'd, and non-53 UDP is
  REJECTed by `SR_CFWD`.

## 5. CA trust in containers

### 5.1 Matrix

Fetch of an allowlisted host (`https://github.com/robots.txt`) through the **intercepting**
proxy. Identical on all three OSes. ✅ = HTTP 200, ❌ = TLS verify failure (fail-closed).

| Image (family / client) | none | bind-mount host bundle over `/etc/ssl/certs/ca-certificates.crt` + `/etc/pki/tls/certs/ca-bundle.crt` | env vars (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=`) + mounts | **runtime shim** (no flags) |
|---|---|---|---|---|
| `curlimages/curl` (Alpine/musl, sets `CURL_CA_BUNDLE=/cacert.pem`) | ❌ | ❌ (reads `/cacert.pem`) | ✅ | ✅ once the shim also overlays image-declared bundle paths (run 4, all OSes) |
| `buildpack-deps:bookworm-curl` (Debian/glibc curl) | ❌ | ✅ | ✅ | ✅ |
| `ubi9/ubi-minimal` (RHEL curl-minimal) | ❌ | ✅ | ✅ | ✅ |
| `python:3.12-slim` (Debian, `urllib`/`ssl`) | ❌ | ✅ | ✅ | ✅ |
| `python:3.12-alpine` (musl, `ssl`) | ❌ | ✅ | ✅ | ✅ |
| `gcr.io/distroless/python3-debian12` | ❌ | ✅ | ✅ | ✅ |
| `python:3.12-slim` + `pip install requests` (certifi) | ❌ | ❌ (certifi bundle) | ✅ | ✅ |
| `node:22-slim` (`fetch`) | ❌ | ❌ (bundled Mozilla store) | ✅ | ✅ |
| `node:22-alpine` | ❌ | ❌ | ✅ | ✅ |
| `eclipse-temurin:21-jdk` (`HttpURLConnection`) | ❌ | ❌ (JDK `cacerts`) | ✅ | ✅ |

Shim edge cases (runtime column): `docker exec` into a shimmed container ✅ (the shim also
patches `runc exec --process`); `--read-only` ✅; `--user 1234` ✅; `--network host` ✅;
**`--runtime runc` ❌** (the user opts out, fail-closed); **service containers ❌** (created
before the action; `docker cp` + `update-ca-certificates` into the running container worked for
`python`, but it's per-image and racy); **`docker build` RUN ❌** (BuildKit doesn't use dockerd's
default runtime, for either the embedded or the docker-container driver).

### 5.2 What the action can actually set

| Container kind | Who creates it, when | Can the action inject trust? |
|---|---|---|
| user `docker run` / compose / testcontainers in a step | dockerd, after the action | **Yes, through the default OCI runtime shim** (`daemon.json`: `runtimes.safer-runc` + `default-runtime`, applied with `SIGHUP`, no restart, running containers kept). There's no daemon-level default env or mount; `DOCKER_*` client env and `~/.docker/config.json` `proxies` only inject proxy vars. The shim is the only hook that works without the user's command line. |
| `uses: docker://…` / Dockerfile actions | the runner, after the action | Yes (shim), **but** default enforce removes docker, so they don't run at all (F2). |
| `services:` | the runner, **before** the action | **No** (already running). Best effort: `docker cp` + per-distro trust update, which is fragile. Use the SNI-only posture instead. |
| job `container:` | the runner, before the action; the action runs **inside** it | **No**, and the action itself can't run (F3). |
| `docker build` RUN steps | BuildKit's executor | **No** (the shim isn't used). Users can `COPY`/secret-mount the CA themselves; otherwise use SNI-only. |

### 5.3 The runtime shim (`p2/safer-runc` in the test repo, ~110 lines of bash + jq)

On `runc create|run --bundle B`, the shim edits `B/config.json`:
- **Bundle overlays.** It finds the image's CA bundle(s): `/etc/ssl/certs/ca-certificates.crt`,
  `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem`, `/etc/ssl/ca-bundle.pem`, plus any
  path the **image** points `SSL_CERT_FILE`/`CURL_CA_BUNDLE`/... at. Symlinks are resolved inside
  the rootfs. It bind-mounts **image bundle + our CA** read-only over each one, which keeps the
  image's own private CAs.
- **Files for env vars.** It mounts `/etc/safer-runner/{ca.pem,bundle.pem,java-cacerts}`.
  `java-cacerts` is a copy of the host JDK's `cacerts`, which v2 already imported the CA into.
- **Env vars.** It adds the env vars only where the image or user hasn't set them, and appends
  to `JAVA_TOOL_OPTIONS`.
- **`exec`.** On `runc exec --process P` it adds the same env to `P`.
- **Then** it `exec`s the real runc unchanged.
- **Failure handling.** Any failure is logged and the container starts unmodified. Trust is a
  compatibility aid, not the control, so failing open here is safe: the container's TLS just
  fails closed at the proxy.

Costs and risks:
- It modifies every container on the VM. `JAVA_TOOL_OPTIONS` makes every JVM print
  `Picked up JAVA_TOOL_OPTIONS` on stderr, which breaks tools that parse `java -version`.
  Consider making Java opt-out.
- It adds a root-owned binary to the container start path.
- It adds `daemon.json` to the integrity baseline.
- It needs `jq`, which is on the image.

## 6. Posture for container TLS the proxy can't intercept (the fork)

Under any option, **non-allowlisted names are blocked by SNI/Host and DNS, and the upstream is
repointed** to the proxy-resolved name. The fork only decides what happens to *allowlisted*
names for clients that don't trust our CA.

| | A. Intercept, no help (today) | B. Intercept + runtime shim | **C. SNI-only for container sources (recommended default)** |
|---|---|---|---|
| Works for `docker run` (10/10 images) | ❌ all HTTPS to allowlisted hosts fails | ✅ 10/10 (shim) | ✅ 10/10, no CA at all (run 3: node, java, curl-alpine, requests) |
| Service containers / `docker build` / `--runtime runc` / pinned clients | ❌ | ❌ | ✅ |
| Analyze mode never breaks containers | ❌ (proven: allowlisted host fails in analyze) | partly | ✅ |
| Host/SNI equality (anti-fronting) | ✅ | ✅ | ❌: `SNI github.com` + `Host: gist.github.com` was served (302) through SNI-only |
| Path/method logging for container traffic | ✅ | ✅ | ❌ (bytes and SNI only) |
| Shared-CDN co-tenancy (C3) for container traffic | closed | closed | **re-opened within the allowlisted SNI's front-end**: same weakness as `passthrough-domains` |
| Moving parts | none | runc shim, `daemon.json`, Java store copy | addon branch on source class |
| Failure mode | fail-closed, noisy | fail-closed for anything the shim misses | n/a |

**Recommendation: C by default (both modes), with `container-tls: intercept` as an opt-in that
also installs the runtime shim (B).**

Why:
1. **Where the container boundary actually holds.** In default enforce, docker is removed, so
   the only containers are **service containers**, and the shim can't reach them. There, A means
   "every service that does HTTPS to an allowlisted host breaks", while C means "it works, by
   name". Where users run their own containers (docker retained, ADVISORY, because docker is
   root), the container boundary is a containment aid against dependencies inside containers,
   not against a determined step. The marginal value of the Host check is lower there.
2. **Analyze must not break anything.** Only C delivers that for containers (option B still
   misses services and builds).
3. **C's weakness is the same one `passthrough-domains` already accepts.** It's bounded by the
   allowlist and the repoint, and it can be narrowed: under C, refuse SNI-only for names known to
   be multi-tenant front doors (e.g. `*.blob.core.windows.net`, which the P0 spike already
   flagged as a fronting risk) and keep them intercepted, i.e. fail-closed for containers.
4. **B stays the right choice for hardened jobs** that run their own containers and want full
   parity (Host check, path logging). As an opt-in, its intrusiveness (every container
   modified, `JAVA_TOOL_OPTIONS` noise) is the user's choice.

**If the human prefers strictness over compatibility:** make **B the default** under
docker-retained enforce. Container kinds the shim can't reach then fail closed: services,
builds, `--runtime runc`. C stays the analyze-mode posture. That's defensible; the cost is
support load from broken builds and service containers.

The human decides: A/B/C default, whether the "multi-tenant front-door denylist under C" is in
P2, and whether Java injection is on by default under B.

## 7. Scope

**P2 (build session):**
- Container traffic rules (§3.1), analyze and enforce, plus ip6 `DOCKER-USER` REJECT.
- conntrack flush of container flows.
- Container DNS (DNAT; nothing else needed).
- F1 fix: dockerd live-restore + restart before the firewall, only when docker is running and
  retained, or when services exist.
- Source classification (second listener, falling back to local-address).
- Container posture C plus `container-tls` input.
- Report: a "Container egress" section (client IP → container name via `docker inspect` at post
  when docker is accessible; otherwise the IP). The addon already logs
  `tls-client-fail: client does not trust the proxy's certificate`, which is the hook for a
  "this container didn't trust the CA; use `container-tls: …`" hint.
- F3 detection and message.
- F2 documentation.
- Tests ported into `v2-test`.

**P2-optional / P3:**
- Runtime shim (B) as the `container-tls: intercept` implementation; it's a contained work item.
- Multi-tenant front-door denylist under C.
- `docker cp` trust into service containers (not recommended).
- Escape hatch for docker container actions under default enforce (F2).
- IPv6-enabled container networks on a runner.
- rootless Docker / Podman (not on hosted images).
- Larger runners.

## 8. Security notes

- **Containers are only a boundary when docker is removed.** With docker retained, any step can
  `docker run --privileged --net=host` or `--runtime runc` and bypass all of this. P2 doesn't
  change v2's "docker = root = ADVISORY" labelling.
- **The shim is root-owned in `/opt/safer-runner/bin`.** `daemon.json` must go into the
  integrity baseline. A failure in the shim leaves trust out, never egress open.
- **`route_localnet` is already broad (review L3).** P2 adds docker0/br-* as further sources of
  127.0.0.1-bound traffic. Only 53 and the proxy port are DNAT targets; the host's other
  loopback services are not exposed (no DNAT to them).
- **IMDS from containers is refused** (proxy: IP-literal Host). That's stricter than the host,
  where IMDS is exempt by IP; that's intended.

## 9. Implementation plan (P1-style build session)

1. **`src/firewall.ts`.**
   - Add `buildContainerNatRules(o)`, `buildContainerForwardRules(o)` and
     `buildIp6ContainerForwardRules(o)` as pure generators with jest snapshot tests, following
     the existing pattern.
   - Apply them in `applyFirewall` when docker is active.
   - Extend `removeFirewall` (PREROUTING / `DOCKER-USER` jumps).
   - Add `conntrack -D` for the Docker subnets (read from `docker network inspect`, or the RFC1918
     set).
   - Add the `CDrop`/`CEgress` prefixes to `setupIptablesLogging`.
2. **Second listener.**
   - Prove on a runner that `mitmdump --mode transparent@<p> --mode transparent@<p+1>` gives
     per-listener `client.sockname`. If it does, add it to `mitmdumpArgs` (new constant,
     `proxy-port + 1`, or a separate input) and DNAT containers to it.
   - Otherwise keep the spike's local-address classifier.
3. **Addon** (`proxy/policy.py` / `policy_core.py`).
   - `container_tls` in `policy.json` (`sni-only` | `intercept`).
   - Source class on every record (`source: host|container`).
   - Under `sni-only`, route allowlisted SNI from containers to the passthrough path (repointed,
     IP-pinned by the existing `server_connect` guard).
   - Optional front-door denylist.
   - Python tests and test-vectors for the classifier and the decision.
4. **F1.**
   - In `egress.ts`, before the firewall: if docker is running and not stopped, set
     `live-restore` (merge `daemon.json`, SIGHUP), then `systemctl restart docker`.
   - Wait for `docker info`. Verify service containers are still running; warn if not.
   - Add `daemon.json` to the integrity baseline.
5. **Inputs.**
   - `container-tls: sni-only|intercept`, default `sni-only`.
   - Under `intercept`, install the runtime shim. The shim becomes a root-owned file shipped in
     the action, like the teardown helper, installed via `daemon.json` + SIGHUP and verified
     with `docker info --format '{{.DefaultRuntime}}'`.
6. **F3.** Detect a job container at the start of `pre`/`main`; enforce → fail with an
   explanatory message, analyze → warning.
7. **Report** (`src/report.ts`). Add a container section: flows by container IP; `tls-client-fail`
   hints; the `CDrop` firewall log.
8. **Tests.** Port into `v2-test`:
   - must-fail: G1–G4, T2–T4, N3;
   - must-pass: T1, T5–T8, N1–N2, posture C for node/java/requests with no CA, a service
     container's egress allowed by name / refused otherwise, a `docker pull` after a service
     container (F1);
   - analyze: no container breakage.

   Run the full matrix on all three OSes.
9. **Docs.** README Limitations:
   - docker = root (ADVISORY);
   - services under default enforce are contained (SNI-only);
   - job containers are unsupported;
   - docker actions vs `disable-docker`;
   - `docker build` trust;
   - fronting under SNI-only.

Rough size: comparable to the P1 firewall + addon work (1–2 sessions), mostly tests.

## 10. Open questions for the human

1. Container TLS default: **C (SNI-only, recommended)**, B (intercept + shim), or A
   (intercept, fail-closed)?
2. Under C, block SNI-only for known multi-tenant front doors (fail-closed for containers)? Is
   that in P2 or P3?
3. Ship the runtime shim (B) in P2 as the `container-tls: intercept` opt-in, or defer it to P3?
4. F2: accept "docker actions don't work under default enforce" (document it), or add a
   narrower docker restriction later?
5. F3: fail hard on job containers in enforce (recommended)?

## 11. Spike log (what ran where)

Test repo `portswigger-tim/safer-runner-action-test`, branch `spike/v2-containers`, workflow
`.github/workflows/p2.yml`, harness `p2/` (`rules.sh`, `safer-runc`, `install-runtime.sh`,
`checks.sh`, `probe.py`, `Get.java`). Action spike branch `spike/v2-containers` = `v2` +
container posture switch in `proxy/policy.py` (spike only, not for `v2`). Evidence artifacts
`p2-evidence-advisory-<os>` per run: flow log, dnsmasq log, iptables-save, dockerd journal, shim
log, service probe log.

| Run | ID | What | Outcome |
|---|---|---|---|
| 1 | 41993890547 | first pass, beta.3 | Rules applied; service container contained after rules (DNS filtered, 853 refused, TLS untrusted). **All image pulls failed with x509 → found F1.** `uses: docker://` fails under default enforce (F2). Job container: action fails with "Unable to locate executable file: sudo", job unprotected (F3). |
| 2 | 41994363798 | + dockerd trust experiments | certs.d ❌; live-restore + restart ✅ (1–3 s, service survives). Gap proven (example.org 200, IMDS 200, 853 open). Full CA matrix. Traffic/DNS/fail-closed green. Build RUN traffic filtered, no CA. `ubuntu-latest` on AWS (F4). Default enforce: service has unfiltered IP egress. |
| 3 | 41995168018 | + posture C (spike addon), proxy-layer denied tests, restart survival, analyze job | Posture C works for node/java/curl-alpine/requests with no CA; denied still blocked; fronting demo 302. **Bug:** host traffic misclassified as container (F5). Analyze: no-CA container fails on an allowlisted host, passes on a would-block host; dockerd pull x509 in analyze too. Rules survive dockerd restart. |
| 4 | 41995767988 | classifier fix, shim jq fix, build under posture C | **8/8 jobs green** (advisory ×3, default-enforce ×3, analyze ×2). Host stays `INTERCEPT` with posture C on; containers `container-sni-only`. Shim 10/10 incl. curl-alpine on every OS; 16 injections, 0 failures. `docker build` RUN allowlisted HTTPS: 200 under C (both drivers), `curl: (60)` under intercept. |

Spike-only artefacts, none of which are production code:
- **Classifier:** the spike's container classifier (`/proc/net/fib_trie`) is a prototype; the
  build should use the second listener (§3.3).
- **Posture switch:** a root-owned file read at addon load (`/etc/safer-runner/container-tls`)
  plus a proxy restart.
- **Rules:** `rules.sh` uses `SR_*` chain names.
