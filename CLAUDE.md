# CLAUDE.md - Developer Guide for Safer Runner Action

> **v2 is `main`** (released as v2.0.0; v1 lives on the `@v1` / `v1.*` tags). The egress control
> is an L7 proxy (mitmproxy) - see [docs/DESIGN-v2.md](docs/DESIGN-v2.md) and
> [docs/V2-P1-NOTES.md](docs/V2-P1-NOTES.md).
> v2 module map: `src/setup/run.ts` (setup orchestration, runs in `pre`); one module per
> service in `src/services/` - `mitmproxy/` (proxy, CA, trust), `coredns/` (CoreDNS resolver,
> replaced dnsmasq - see [docs/DNS-COREDNS.md](docs/DNS-COREDNS.md); allowlist entries are EXACT
> by default), `iptables/`, `docker/`, `sudo/` - each a pure `config.ts` and an `index.ts` of
> effects; `src/policy.ts`, `src/setup/selftest.ts`, `src/integrity/`, `src/report/`;
> the GitHub list is `src/config/github-domains.generated.ts` (`npm run gen:domains`);
> the addon is `proxy/policy.py` + `proxy/policy_core.py` (`npm test` runs jest + the Python
> tests). The suggested `http-filter` is built by `proxy/suggest.py` (run by the post step via
> `src/report/suggest.ts`; the report only renders it, as YAML written by the `yaml` library
> that `src/config/inputs.ts` parses the input with). `policy_core.Policy.load` checks `policy.json`
> against the `src/policy.ts` contract (`version: 1`) and fails closed. Real-runner tests run
> from throwaway branches of the test repo `portswigger-tim/safer-runner-action-test`.
> **v2 inputs:** `mode`, `allowed-domains`, `passthrough-domains`,
> `block-risky-github-subdomains`, `dns-servers`, `disable-sudo`, `sudo-config` (YAML list of exact
> sudo command lines kept under `disable-sudo`; `parseSudoConfig` in `src/services/sudo/config.ts`), `docker` (keep | remove-group |
> stop), `fail-on-tampering`, `http-filter` + `allow-github-platform` (L7 method/path filter -
> [docs/DESIGN-L7-path-method.md](docs/DESIGN-L7-path-method.md); matcher `HttpFilter` in
> `proxy/policy_core.py`, platform list `GITHUB_PLATFORM_ENDPOINTS`) - parsed in `src/config/inputs.ts`.
> `fail-on-tampering` is mode-aware (no action.yaml default; unset = on in enforce). `disable-sudo`
> unset means remove sudo, and `docker` unset means `remove-group`, in both modes: `mode` decides
> apply (enforce) or evaluate (analyze never changes sudo or docker access; it reports what
> enforce would block and suggests a config) - see [docs/DESIGN-unified-analyze.md](docs/DESIGN-unified-analyze.md).
> Removed (v1 or early beta only - do not document as current): v1's `sudo-config` format, `disable-docker`, `stop-docker`, `primary-dns-server`,
> `secondary-dns-server`, `proxy-port`, `proxy-stream-large-bodies`, `container-tls`.

This guide helps developers understand, maintain, and extend the Safer Runner Action codebase.
User-facing documentation is in [README.md](README.md); design notes are in `docs/`.

## 🏗️ Architecture Overview

### What the action does

On a GitHub-hosted Ubuntu runner (24.04 / 26.04), the action puts four controls in place before
any other step runs:

1. **Proxy** - all HTTP and HTTPS is forced through a transparent, TLS-terminating mitmproxy.
   It checks the SNI and the `Host` header against the allowlist and connects to the *name*,
   never to the IP the client picked. This is the primary egress control.
2. **DNS** - a default-deny CoreDNS resolver answers allowlisted names (exact FQDN) and
   returns NXDOMAIN for everything else. It is a second layer, and it stops DNS tunnelling.
3. **Firewall** - iptables rules force 80/443 to the proxy and all port 53 to CoreDNS. In
   enforce they reject everything else. This is the transport-enforcement and fail-closed
   layer, not the primary control. On GitHub-hosted 24.04 and 26.04 `iptables` is already
   `iptables-nft` (nftables backend).
4. **Privilege** - in enforce, sudo and docker access are removed from the runner user. Without
   this, any step could remove the other three.

### Core Components

```
src/
├── pre.ts           # pre step: runs the full setup (runSetup) before any other step
├── main.ts          # main step: no-op if pre completed; otherwise runs setup
├── post.ts          # post step: checks integrity, writes the job summary, fail-on-tampering
├── policy.ts        # builds policy.json; TS mirror of the addon's pattern matching
├── flowlog.ts       # parser for the proxy's JSON-lines flow log
├── constants.ts     # paths, user names, chain names, pinned versions and sha256 sums
├── config/
│   ├── inputs.ts                   # reads and validates all inputs; mode-aware defaults; http-filter
│   ├── github-domains.ts           # GitHub allowlist (meta API + static), platform endpoints
│   └── github-domains.generated.ts # snapshot of api.github.com/meta (npm run gen:domains)
├── setup/
│   ├── run.ts       # setup orchestration (runSetup), setup marker, job-container guard, log dir
│   └── selftest.ts  # live self-tests run on every job (sni-block, repoint, dns-exact)
├── services/        # one per service: config.ts (pure render) + index.ts (effects, via the Host)
│   ├── mitmproxy/   # pinned mitmdump, proxy user, policy.json, unit, ports;
│   │                #   ca.ts (per-run CA), trust.ts (system store, GITHUB_ENV, Java keystores)
│   ├── coredns/     # pinned CoreDNS, random DNS user, Corefile (buildCorefile), unit, resolv.conf
│   ├── iptables/    # iptables / ip6tables rule generators, atomic apply, rsyslog firewall log
│   ├── docker/      # dockerd restart for CA trust; docker access removal and verification
│   └── sudo/        # sudo logging (classic sudo and sudo-rs), the restricted sudoers, sudo removal
├── integrity/
│   ├── baseline.ts  # integrity baseline: SHA256 of files and iptables chains, stored root-only
│   └── check.ts     # post step: one read, one comparison -> verdict + summary details
├── system/          # the Host port (host.ts), writeFiles, transient units, pinned installs,
│                    #   shared types and readiness tokens (tokens.test.ts)
└── report/          # the job summary
    ├── logs/        # DNS / firewall / sudo log parsers (the flow log's is src/flowlog.ts)
    ├── aggregate/   # flows, containers, http-filter (and its suggestion as YAML)
    ├── render/      # Markdown
    ├── redact.ts    # redaction of encoded-looking names and hidden paths in the summary
    └── suggest.ts   # runs proxy/suggest.py (python3 -I) for the suggested http-filter
proxy/
├── policy.py            # mitmproxy addon: wiring, layer selection, repoint, flow log
├── policy_core.py       # pure policy logic (no mitmproxy import): patterns, decisions, HttpFilter
├── suggest.py           # builds the suggested http-filter from allowed requests (post step)
├── sudo_suggest.py      # builds the suggested sudo-config from the workflow's sudo use (post step)
├── policy_core_test.py  # Python unit tests for the policy core
├── suggest_test.py      # Python unit tests for the suggester
├── sudo_suggest_test.py # Python unit tests for the sudo-config suggester
└── test-vectors.json    # shared vectors checked by BOTH the Python and the jest tests
```

### Build Process

```bash
npm run build        # tsc, then ncc: lib/main.js -> dist/main/index.js
npm run build:pre    # ncc: lib/pre.js  -> dist/pre/index.js
npm run build:post   # ncc: lib/post.js -> dist/post/index.js
npm run package      # clean + prettier --write + test + build all three (recommended)
npm test             # jest + the Python tests (npm run test:py)
npm run gen:domains  # regenerate src/config/github-domains.generated.ts
```

**Critical**: Always run `npm run package` and commit `dist/*/index.js` - GitHub Actions
executes the compiled bundles, not the TypeScript source. CI (`.github/workflows/ci.yml`)
reruns `npm run package` and fails if anything tracked changes, so `dist/` must be
byte-identical to a clean rebuild. The proxy addon files `proxy/policy.py` and
`proxy/policy_core.py` are not bundled: setup copies them from the action checkout to the
root-owned `/opt/safer-runner/proxy/`.

`.pre-commit-config.yaml` runs the same checks (format, `tsc --noEmit`, tests, dist sync)
on `git commit`.

### Lifecycle (pre / main / post)

The action is a `node24` JavaScript action with `pre`, `main` and `post` entry points
(`action.yaml`).

1. **pre** (`pre.ts`) - applies the **full policy**, not just monitoring, before any other
   step. That includes the `pre` steps of actions that appear later in the job.
   - A bad `mode` value fails the step at once.
   - If setup fails in enforce, `pre` fails the job (fail closed). In analyze it warns, and
     `main` retries - unless the setup marker was already written (sudo logging and the
     baseline come after it), when `main` will not retry. Analyze never changes sudo, so nothing
     is left half-applied.
2. **main** (`main.ts`) - if the root-owned setup marker `/etc/safer-runner/setup-complete`
   exists, it does nothing. Otherwise (for example a local `uses: ./` action) it runs setup.
3. **post** (`post.ts`) - verifies integrity against the baseline, builds the job summary, and
   applies `fail-on-tampering`. The proxy and firewall stay up: the runner's own "Complete job"
   traffic still goes through them, and the VM is destroyed afterwards. The CA private key is
   never deleted by the action: it lives only on tmpfs and dies with the VM (ephemeral runners
   are the only supported model).

### Setup order (`src/setup/run.ts: runSetup`)

Each step depends on the one before it. Where a step needs an earlier one, it takes that
step's readiness token (a branded type only the owning module can mint, listed in
`src/system/tokens.test.ts`), so the wrong order does not compile; `src/orchestration.test.ts`
checks the same order (L1-L28) on a recording fake runner.

1. Job-container guard: a job `container:` is unsupported (enforce fails, analyze warns).
2. Allowlist: GitHub domains from `api.github.com/meta` (before DNS changes), plus user entries.
   Build `policy.json`.
3. Install the pinned CoreDNS and mitmdump, and `conntrack`, in parallel.
4. Create the DNS user and proxy user; install the addon, write the policy, generate the CA.
5. Start the proxy (it waits for the addon's own startup self-test).
6. Trust: CA in the system store, exported variables via `GITHUB_ENV`, Java keystores.
7. DNS: write the Corefile, start CoreDNS, then point `resolv.conf` at it.
8. If docker runs, restart dockerd so it trusts the CA (F1).
9. Firewall: nat REDIRECT and filter chains, plus the container rules when docker runs.
10. Live self-tests (`src/setup/selftest.ts`).
11. Docker policy (`docker` input; enforce only, analyze never changes it), then verify real
    docker access. In enforce, a removal that did not take fails setup.
12. Write the setup marker, set up sudo logging, capture the integrity baseline, and
    **restrict sudo last**.

## 🛡️ Security Architecture

### Layers

1. **L7 proxy (primary)** - `src/services/mitmproxy/`, `proxy/policy.py`, `proxy/policy_core.py`
   - mitmdump runs transparent, as the dedicated user `safer-runner-proxy`, in a transient
     systemd unit (`Restart=always`) outside the runner's process tree.
   - Two transparent listeners on a free port pair (20000-32766): one for the host, one for
     containers. The addon classifies the source by the listener, never by address.
   - The addon owns layer selection. It checks the SNI at the ClientHello, the `Host` on each
     request (and `Host == SNI` inside intercepted TLS), and blocks no-SNI and IP-literal TLS.
   - **Repoint**: the upstream is the SNI or Host name, resolved once by the proxy and
     pinned. An upstream IP guard refuses internal addresses (loopback, link-local, RFC 1918,
     CGNAT and others).
   - Three host classes: allow (intercepted), passthrough (SNI-only, never decrypted;
     `hosted-compute-*.githubapp.com` is always included), and deny.
   - Containers get SNI-only treatment for allowlisted names (no CA needed); Azure storage
     "front doors" stay intercepted. See [docs/DESIGN-v2-P2-containers.md](docs/DESIGN-v2-P2-containers.md).
   - `http-filter` is a gate after the host check: method and path rules on chosen hosts
     (`policy_core.HttpFilter`). It only narrows; it never grants access.
   - mitmproxy is pinned (`MITMPROXY_VERSION` + sha256 in `constants.ts`). The addon refuses
     to start on any other version.
   - Every hook fails closed.

2. **DNS (CoreDNS)** - `src/services/coredns/` (the Corefile: `buildCorefile` in `config.ts`)
   - Default-deny. Allowlist entries are **exact FQDNs** by default: `x` is exactly `x`,
     `*.x` is subdomains, `.x` is both, `a*.x` is a one-label glob.
   - enforce: allowed names are forwarded to `dns-servers`; everything else gets NXDOMAIN
     locally. analyze: everything is forwarded; names enforce would refuse are logged
     `WOULD_BLOCK`.
   - Runs as a random DNS user in the unit `safer-runner-dns`. Logs to `dns.log`.
   - The proxy and DNS use the same pattern set, so they cannot disagree.
   - Details: [docs/DNS-COREDNS.md](docs/DNS-COREDNS.md).

3. **Firewall (iptables)** - `src/services/iptables/`
   - Rulesets are generated as `iptables-restore` text (pure functions in `config.ts`,
     snapshot-tested in `src/services/iptables/__snapshots__/`) and applied atomically with
     `iptables-restore --noflush` into chains the action owns. The image's own rules are
     left alone.
   - nat: `SAFER_RUNNER_NAT` redirects 80/443 to the proxy and all port 53 to CoreDNS. The
     proxy user, the DNS user, loopback, local bridges and the Azure platform IPs are exempt.
   - filter: `SAFER_RUNNER_OUT`. enforce: allow loopback, the proxy user on 80/443, the DNS
     user to its upstreams, and the Azure platform; reject the rest. analyze: allow, log new
     non-proxied connections, reject QUIC (UDP/443). Rules are interface-agnostic, so a
     renamed or extra NIC fails closed.
   - ip6tables: no IPv6 path through the proxy. enforce rejects non-loopback IPv6.
   - Containers: `SAFER_RUNNER_CNAT` (nat PREROUTING DNAT from the Docker bridges) and
     `SAFER_RUNNER_CFWD`, hooked from Docker's `DOCKER-USER` chain. In enforce, a missing
     `DOCKER-USER` chain fails setup.
   - Firewall events reach `firewall.log` through an rsyslog rule (`loggingRule` in `config.ts`).

4. **Privilege (sudo, docker)** - `src/services/sudo/`, `src/services/docker/`
   - **sudo**: two implementations, classic sudo (Ubuntu ≤24.04) and sudo-rs (default on 26.04),
     found by `detectSudoFlavour` (`sudo --version`).
     - Logging goes to `/var/log/safer-runner/sudo.log`. Classic sudo: `Defaults logfile=` drop-in
       `/etc/sudoers.d/00-sudo-logging`. sudo-rs has no logfile support, so an rsyslog rule
       `/etc/rsyslog.d/10-sudo-safer-runner.conf` copies its syslog messages to the same file.
     - `disable-sudo` in enforce (`restrictSudo`) rewrites `/etc/sudoers.d/runner` to allow only
       exact, read-only validation commands (`getValidationSudoCommands()`), plus the job's
       `sudo-config` lines as a second alias run as `(root)`. A command with no arguments is
       written `path ""` (bare, sudoers allows ANY arguments). It is validated with the active
       `visudo` before it is moved into place; a rejected file fails setup. `restrictSudo` only
       accepts a render that restricts, so analyze cannot restrict (L26); the installed file is
       checked line by line (L27). Any `sudo-config` makes enforce ADVISORY.
     - Analyze: the post step evaluates the policy against the sudo log (`evaluateSudo`), lists
       what enforce would block, and suggests a `sudo-config` (`proxy/sudo_suggest.py`, exact
       lines only, never `*`; run by `src/report/suggest.ts`).
     - Sudoers text must be valid for BOTH implementations: no wildcards among command
       arguments (sudo-rs accepts only a lone trailing `*`), no `Defaults!<alias>`, no
       `log_allowed`.
     - Order: sudo logging, then the integrity baseline, then the restriction **last** (each
       takes the previous step's token). The action's own sudo commands are filtered from
       reports through `INTERNAL_SUDO_COMMANDS`.
   - **docker**: `docker: remove-group` removes the runner user from the `docker` group and
     locks the socket to `root:root 0600`; `stop` stops and disables the daemon; `keep` leaves it.
     Setup then verifies the real access (`readDockerState`). Only enforce changes docker access:
     `planDocker` (`config.ts`) makes the `ApplyingDocker` that the functions changing access
     require, and only in enforce, so analyze changing it does not compile (L28 checks the
     transcript). Analyze is treated as `keep` (the dockerd CA restart and the container rules
     still apply).
   - **Defaults** (`src/config/inputs.ts`): unset `disable-sudo` is `true` and unset `docker` is
     `remove-group`, in both modes (analyze only evaluates them). Unset `fail-on-tampering` is
     mode-aware: on in enforce, off in analyze. An explicit value always wins. Enforce with sudo
     or docker kept is **ADVISORY**: the controls are applied, but they are not an enforced
     boundary.

### Integrity check - `src/integrity/`

**Purpose**: a tripwire that detects changes to the security configuration during the job.
It is advisory, not tamper-proof: the post step runs as the runner user from files the job can
modify. See [docs/DESIGN-post-run-integrity.md](docs/DESIGN-post-run-integrity.md).

**Flow**:
1. **Baseline** - setup captures SHA256 checksums when it is done (`captureBaseline` in
   `baseline.ts`), after sudo logging is on and before sudo is restricted.
2. **Job runs** - potentially hostile code executes.
3. **Verify** - the post step (`checkIntegrity` in `check.ts`) reads the baseline and the current
   state once and compares them once; the `fail-on-tampering` verdict and the summary's
   integrity details both come from that one comparison.

**Baseline file**: `/etc/safer-runner/validation-state.json`, `root:root 0600` (constant
`VALIDATION_STATE_FILE`). The runner user cannot read or rewrite it. The post step reads it
with `sudo -n cat <exact path>`, an exact allowlist entry that survives `disable-sudo`. A
missing or unreadable baseline counts as "not intact".

**Monitored**:
- Files (`CRITICAL_FILES`): `/etc/safer-runner/Corefile`, `/etc/resolv.conf`,
  `/etc/systemd/resolved.conf.d/no-stub.conf`, `/etc/safer-runner/policy.json`,
  `/opt/safer-runner/proxy/policy.py`, `/opt/safer-runner/proxy/policy_core.py`; plus the sudo
  logging config for the active sudo flavour, and `/etc/docker/daemon.json` when setup wrote it.
- iptables chains (`IPTABLES_CHAINS`): `INPUT`, `OUTPUT`, `FORWARD`, `SAFER_RUNNER_OUT`,
  `nat:OUTPUT`, `nat:SAFER_RUNNER_NAT`, `DOCKER-USER`, `SAFER_RUNNER_CFWD`,
  `nat:SAFER_RUNNER_CNAT` (a container chain that does not exist lists as empty).

Every file read and chain listing the post step needs is added to the sudoers allowlist
automatically (`getValidationSudoCommands()`).

## 📊 Logging & Reporting

### Runtime files (`constants.ts`)

All logs are in `/var/log/safer-runner/` and are readable without sudo:

| File | Written by | Content |
|---|---|---|
| `proxy-flows.jsonl` | the addon | one JSON line per decision (TLS, HTTP, upstream, startup) |
| `dns.log` | CoreDNS | one line per query: `ALLOW` / `BLOCK` / `WOULD_BLOCK` |
| `firewall.log` | rsyslog | iptables LOG lines (prefixes `SaferRunner-Drop:`, `-Egress:`, `-CDrop:`, `-CEgress:`) |
| `sudo.log` | sudo / rsyslog | sudo usage |
| `selftest.json` | setup | self-test results |

Config and state are root-owned in `/etc/safer-runner/` (`policy.json`, `Corefile`, `ca.pem`,
`setup-complete`, `validation-state.json`). Binaries and the addon are in `/opt/safer-runner/`.
The CA private key is only on tmpfs, in `/run/safer-runner/proxy`, and dies with the VM.

The raw logs are **not redacted**. Never upload them from a public repository.

### Job summary (`src/report/`, called from `post.ts`)

`post.ts` reads the flow log, firewall log, DNS log and sudo log, drops the setup self-test
traffic, and calls `buildReport`. The summary shows the verdict first (mode, ADVISORY label,
post-run status chip), then traffic grouped by cause: blocked or would-block hosts, allowed
hosts, container egress, the `http-filter` section, sudo usage, and diagnostics (self-tests,
DNS refused, integrity). In analyze it suggests an `allowed-domains` block.

- Names go through `src/report/redact.ts`: labels that look encoded are shown as `‹redacted›`; refused
  request paths are shown as `‹path hidden›`. This is best effort, not a guarantee.
- Full lists also go to the job log, redacted the same way.
- The `http-filter` section lists requests the filter refused and suggests a filter built from
  observed traffic (it splits reads from writes, templates variable path segments, and keeps
  sensitive write endpoints path-specific). The suggestion is advisory and never applied
  automatically. Python owns the content: `proxy/suggest.py` (next to the matcher it must agree
  with) produces structured rules (host to a list of path and methods), and `src/report/suggest.ts`
  runs it with `python3 -I`. TypeScript owns the YAML: `httpFilterYaml`
  (`src/report/aggregate/http-filter.ts`) writes
  the rules with the same `yaml` library that parses the input (double-quoted path keys, block
  literal), so a pasted suggestion reads back as printed. If the Python run fails, the report
  shows no suggestion.

## 🔧 Development Workflows

### Making Changes

1. **Modify source** - edit `src/*.ts` and/or `proxy/*.py`.
2. **Build & test** - `npm run package` (formats, tests, rebuilds `dist/`).
3. **Commit source + dist** - always commit both.
4. **Push** - use `GIT_SSH_COMMAND="ssh -o IdentitiesOnly=yes" git push` to avoid SSH agent
   certificate issues.
5. **Test on real runners** - from a throwaway branch of the test repo
   `portswigger-tim/safer-runner-action-test` (matrix: `ubuntu-latest`, `24.04`, `26.04`).
   This repository's own workflows are `ci.yml`, `release.yml` and `update-github-domains.yml`;
   they do not run the action on a runner.

### Keep the three pattern matchers in step

The allowlist pattern semantics exist in three places: `compilePattern` (`src/policy.ts`),
`compile_pattern` (`proxy/policy_core.py`) and `buildCorefile` (`src/services/coredns/config.ts`).
`proxy/test-vectors.json` drives all of them. When you change semantics, change the vectors
first and make all three suites pass. The `http-filter` path glob and the self-test probe are
covered the same way.

### Adding New Security Features

1. **Proxy / L7 policy** - `proxy/policy_core.py` (pure logic, unit-tested) and `proxy/policy.py`
   (wiring). Carry new settings through `PolicyConfig` in `src/policy.ts` and `policy.json`.
   The addon must refuse to start, not run open, if it cannot load its config.
2. **DNS** - `src/services/coredns/config.ts` (the Corefile) and `index.ts` (the service).
3. **Firewall** - add a pure generator in `src/services/iptables/config.ts` with a snapshot test,
   apply it in `configure()` (`index.ts`), and add any new chain to `IPTABLES_CHAINS` in
   `src/integrity/baseline.ts`.
4. **Integrity** - add files to `CRITICAL_FILES` in `src/integrity/baseline.ts`. The sudoers
   allowlist follows automatically.
5. **Privilege** - `src/services/sudo/` and `src/services/docker/`. Keep sudoers text valid for
   both sudo flavours.
6. **Reporting** - `src/report/`. Anything shown from a blocked name or path must go through
   `src/report/redact.ts`.
7. **Inputs** - declare in `action.yaml`, parse in `src/config/inputs.ts`, document in `README.md`.
8. **A new setup step** - put pure rendering in the service's `config.ts` and effects in its
   `index.ts`, running every command through the `Host` (`src/system/host.ts`). If its order
   matters, take the earlier step's readiness token (declared and minted only in the owning
   module), register any new token in `src/system/tokens.test.ts`, and add the ordering
   invariant to `src/orchestration.test.ts` with a mutation check. Restricted files (0600,
   sudoers) and writes that change behaviour are named steps, never `writeFiles`.
   Mode-aware inputs have no `action.yaml` default, so "unset" differs from an explicit value.

### Debugging on a runner

**Services** (the proxy and resolver are transient systemd units):
```bash
systemctl status safer-runner-proxy safer-runner-dns
journalctl -u safer-runner-proxy --no-pager | tail -50
```

**Logs** (readable without sudo):
```bash
tail proxy-flows.jsonl dns.log firewall.log sudo.log selftest.json  # in /var/log/safer-runner/
dig @127.0.0.1 example.com        # DNS: NXDOMAIN in enforce unless allowlisted
```

**Firewall** (needs sudo, so not after `disable-sudo` except for the allowlisted chain listings):
```bash
sudo iptables -L SAFER_RUNNER_OUT -n -v --line-numbers
sudo iptables -t nat -L SAFER_RUNNER_NAT -n -v --line-numbers
sudo iptables -L DOCKER-USER -n --line-numbers
```

**Integrity baseline**: `sudo cat /etc/safer-runner/validation-state.json` (root-owned 0600).

## 🧪 Testing Strategy

**Run tests**: `npm test` (jest, then the Python tests). One suite: `npm test -- src/services/iptables`.
Python only: `npm run test:py`.

**Jest suites** (next to the code in `src/`):
- `orchestration.test.ts` - `runSetup` and the post step on a recording fake runner that fakes
  only external boundaries (`@actions/*`, `fs`, `os`, `dns`, `net`, randomness, timers).
  Snapshots the command transcript and the files setup writes, checks the ordering invariants
  L1-L28, and proves each one bites with a mutation check. Also pre then main around the setup
  marker.
- `system/tokens.test.ts` - every readiness token is minted only by its owning module and has an
  ordering invariant; `system/system.test.ts` - `writeFiles` and transient units.
- `services/*` - per service: `coredns` (config + snapshot, index), `mitmproxy` (index, trust),
  `iptables` (+ snapshot), `docker`, `sudo`; effects run against `recordingHost`
  (`src/system/testing.ts`).
- `setup/run`, `setup/selftest`, `pre`, `integrity/baseline` (capture and the one-pass check),
  `config/inputs`, `config/github-domains`, `policy`, `scripts/gen-github-domains`.
- Report: `report.test.ts` (+ fixture `__fixtures__/beta2-enforce-flows.jsonl`),
  `report.golden.test.ts` (golden summaries + the redaction canary), `report/redact`,
  `report/suggest`, `report/logs/*` (dns, sudo; fixture `coredns.log`).

**Python**: `proxy/policy_core_test.py` and `proxy/suggest_test.py`, plus the shared `proxy/test-vectors.json` (which also pins the suggester's output).

**Real-runner tests** live in the test repo (not here): allowed hosts for curl, git, node,
python and docker; negative tests (`--resolve` to a shared-CDN IP, spoofed SNI, domain fronting,
IP-literal and no-SNI TLS, a hole in the REDIRECT, IPv6, Azure DNS); container egress; and the
agent-survival checks (checkout, artifacts, cache). Run each on `ubuntu-latest`, `24.04` and
`26.04`.

**Self-tests** run on every job during setup (`src/setup/selftest.ts`) and fail setup in enforce:
`sni-block` (an SNI-level block fired), `repoint` (the proxy ignores the client's IP), and
`dns-exact` (a random subdomain of an exact entry is refused).

### Manual checks

```bash
curl -sS -m 5 https://example.org           # blocked in enforce (not allowlisted)
curl -sS https://api.github.com/zen         # allowed (GitHub's own endpoints)
curl --resolve github.com:443:192.0.2.1 https://github.com/robots.txt   # still reaches github.com: repoint
```

## 🚨 Security Considerations

### Limitations

The README and [docs/LIMITATIONS.md](docs/LIMITATIONS.md) are the authority. In short:
1. **Allowlisted hosts are full-capability channels** (use `http-filter` to narrow them).
2. **Wildcard allowlist entries are a DNS channel** to the whole zone.
3. **Only TCP 80/443 is proxied**; other ports are rejected in enforce.
4. **Anything with root defeats the controls**: sudo or docker kept in enforce is ADVISORY.
5. **Job summary and tamper check are advisory**; redaction is best effort.
6. **Passthrough hosts are SNI-only** (no Host check, no path filter).

### Defence in depth

Network filtering is one layer. Recommended complements: least-privilege `GITHUB_TOKEN`, pinning
actions by SHA, dependency scanning, runtime monitoring. See
[docs/CICD-GOOD-PRACTICE.md](docs/CICD-GOOD-PRACTICE.md).

## 📝 Common Tasks

### Update the GitHub allowlist

At runtime the list comes from `api.github.com/meta` (`.domains.actions`), with the generated
snapshot as fallback (`resolveGitHubDomains()` in `src/config/github-domains.ts`). To refresh the
snapshot run `npm run gen:domains`; the scheduled workflow `update-github-domains.yml` does this
weekly. Names the meta list lacks go in `GITHUB_EXTRAS` (each needs a justification).
Over-broad shared suffixes are refused through `DANGEROUS_BROAD_DOMAINS`. The deny list for
`block-risky-github-subdomains` is `RISKY_GITHUB_SUBDOMAINS`.

### Update the GitHub platform endpoints (`http-filter`)

Edit `GITHUB_PLATFORM_ENDPOINTS` in `src/config/github-domains.ts`. Each entry is an explicit
`(host, path, methods)` - never a blanket read rule. `essential: true` entries (the job's control
plane) always apply on a filtered host; the rest apply only where none of the job's rules matches.
Grow the list from observed real-runner traffic (the flow log).

### Bump a pinned binary

Change the version and sha256 together in `src/constants.ts` (`MITMPROXY_*`, `COREDNS_*`). For
mitmproxy also change `PINNED_MITMPROXY_VERSION` in `proxy/policy.py`: the addon uses mitmproxy
internals and refuses any other version.

For CoreDNS also change `COREDNS_ASSET_ID`: the same release asset through the GitHub REST API,
tried first (a different front door from `github.com/.../releases/download`, which has failed on
its own). The command to look it up is next to the constant. Every source in `*_SOURCES` is
checked against the one pinned sha256 (`downloadVerified` in `src/system/install.ts`: each retry
round tries every source in order, backoff between rounds).

### Add a domain-purpose or report change

Edit `src/report/` (rendering in `render/report.ts`) and its tests. Run
`npm test -- src/report src/report.test.ts src/report.golden.test.ts`; update the golden
snapshot only when the change is intended.

### Add an input

1. Add it to `action.yaml` (mode-aware inputs: no `default`).
2. Parse it in `src/config/inputs.ts` (`readInputs`, the `Inputs` interface) and add tests.
3. Thread it through `src/setup/run.ts` / `policy.ts` to where it takes effect.
4. Document it in `README.md`, and add a line to `docs/RELEASE-NOTES.md` at release time.

`http-filter` is the one structured input: a YAML map of host to path pattern to methods (JSON
works too, as it is a subset of YAML). `parseHttpFilter` in `src/config/inputs.ts` reads it with the `yaml`
library (`parseDocument`, core schema, YAML 1.2, strict) and then checks one shape. It fails the
step, never last-wins or ignores, on a duplicate host or path, an anchor, alias, tag, document
marker, deeper nesting, or methods that are not a string or a list of strings. YAML escapes in
keys are decoded. In an inline `{ }` rule, a word after a comma with no `:` continues the
methods (`{ "*": GET, HEAD }`); no value means `NONE`. `buildHttpFilter` in `policy.ts`
compiles the result and emits the guardrail warnings. `yaml` is a production dependency,
bundled into `dist/` by ncc.

### Release

Tags `vX.Y.Z` trigger `release.yml`, which checks that the tag is on a release branch, that the
tests pass, and that a clean rebuild of `dist/` is byte-identical to the committed one, then
attests the build provenance. v2 has **no floating tag**: never create `@v2`; users pin an exact
version or a SHA. v1 keeps its moving `@v1`. After a release, bump the README examples to the new
version. Release notes describe security fixes as "hardening" and carry no exploit detail. See
[docs/VERIFYING.md](docs/VERIFYING.md) and [docs/security/repo-hardening.md](docs/security/repo-hardening.md).

## 📚 Key Dependencies

**Production**:
- `@actions/core` - GitHub Actions runtime (inputs, outputs, logging, summary)
- `@actions/exec` - command execution (sudo, iptables-restore, systemd-run)

**Runtime tools installed by the action** (pinned by sha256, `constants.ts`; amd64 only):
- mitmproxy (`mitmdump`) and CoreDNS, from the upstream release tarballs
- `conntrack` from apt

**Development**:
- `typescript`, `@vercel/ncc` (bundles each entry point), `jest` + `ts-jest`, `prettier`
- Python 3 (unittest) for the addon tests

**Node.js built-ins**: `crypto` (SHA256 for the integrity check and downloads), `fs`, `dns`, `net`.

## 🐛 Troubleshooting

### Build Issues
- Type errors: `npx tsc --noEmit`.
- CI says `dist/` is out of date: run `npm run package` and commit the result.
- Prettier changes files in `npm run package`: commit them (CI checks the tree is clean).

### Runtime Issues

**Everything is blocked, including the job's own steps**:
- The proxy may be down. Check `systemctl status safer-runner-proxy` and `proxy-flows.jsonl`.
  The REDIRECT then hits a closed port, which is the fail-closed behaviour.
- A client that does not trust the CA fails with a TLS error on an allowlisted host. Check the
  exported variables (`src/services/mitmproxy/trust.ts`), or add a single-tenant host to `passthrough-domains`.

**DNS not working**:
- `/etc/resolv.conf` should say `nameserver 127.0.0.1`.
- `systemctl status safer-runner-dns`, then `dns.log`. Test with `dig @127.0.0.1 github.com`.
- Remember exact semantics: `example.com` does not allow `www.example.com`.

**Connections blocked unexpectedly**:
- Look at the flow log for the verdict and reason (`sni-not-allowed`, `host-not-allowed`,
  `upstream-ip-forbidden`, `method-not-allowed`, `path-not-allowed`).
- Rejected non-proxied traffic shows in `firewall.log` (`SaferRunner-Drop:`).

**Validation failures**:
- Check which file or chain the post step names. The baseline is
  `/etc/safer-runner/validation-state.json` (root-owned 0600).
- A baseline that is missing or unreadable counts as "not intact".

**Pre step not running**:
- Check the `pre` log in the job output, and that `dist/pre/index.js` is committed and current.
- Without `pre`, `main` runs setup late (so other actions' `pre` steps are not covered).

### Integration Issues

**Summary not showing**:
- `dist/post/index.js` must be current. Check the post step log for errors; a report failure
  is a warning and never skips `fail-on-tampering`.

**GitHub Actions failing**:
- `action.yaml` must reference `dist/pre/index.js`, `dist/main/index.js` and `dist/post/index.js`.

## 🏗️ Architecture Decisions

Background for these is in [docs/DESIGN-v2.md](docs/DESIGN-v2.md) and
[docs/V2-P1-NOTES.md](docs/V2-P1-NOTES.md).

### Why hostname (L7) instead of IP allowlisting?

IP allowlists admit whole shared CDNs and clouds, so `curl --resolve attacker-host:443:<allowed-ip>`
reaches an attacker's site. A transparent proxy that reads the SNI and Host and connects to
the name closes that. A naive transparent proxy is worse: by default mitmproxy dials the IP the
client chose. The repoint rule is therefore mandatory.

### Why does `pre` apply the full policy?

So later actions' `pre` steps are covered too, not only monitored. `main` is a fallback.

### Why is the firewall not the primary control?

The proxy and CoreDNS decide what is allowed. iptables only forces traffic into them and
rejects what bypasses them. It keeps the iptables interface (nftables underneath) because Docker
programs its own rules through it and the action hooks `DOCKER-USER`.

### Why a root-owned install and baseline?

The action checkout and `/tmp` are writable by the runner user, and the proxy unit re-reads its
script on restart. The addon, policy, Corefile, CA path and integrity baseline therefore live
in root-owned `/opt/safer-runner` and `/etc/safer-runner`.

### Why does the post step keep the proxy running?

The runner's "Complete job" request still goes through it. The CA key is never written to
persistent disk: it is on tmpfs and dies with the VM, so the post step leaves it alone. A proxy
crash would restart with a new CA, which fails closed.

---

## 💡 Pro Tips

1. **Always test both modes** - analyze and enforce behave differently.
2. **Use `npm run package`** - it formats, tests and rebuilds all three bundles.
3. **Verify `dist/` is committed** - GitHub Actions runs the bundles, and CI checks them.
4. **Check the flow log first** - `proxy-flows.jsonl` shows every decision and its reason.
5. **Keep pattern semantics in the shared vectors** - `proxy/test-vectors.json`.
6. **Never print raw blocked names or paths in the summary** - use `redact.ts`.
7. **Test edge cases** - IP literals, no-SNI TLS, Host/SNI mismatch, containers, sudo-rs.
8. **Fail closed** - on a parse error in the addon, the Corefile, or the sudoers file, refuse.
9. **Update this file** when you change the architecture.

## 📞 Getting Help

- **GitHub Issues** - bug reports and feature requests
- **Security** - report privately; see [SECURITY.md](SECURITY.md)
- **Docs** - [README.md](README.md) for users; `docs/` for design notes

Remember: this action protects against supply chain attacks. Changes should be thoroughly
tested and reviewed for security implications.
