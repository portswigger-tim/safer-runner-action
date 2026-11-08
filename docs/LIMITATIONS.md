# Limitations

Safer Runner Action hardens one layer: network egress. It is not a complete sandbox.
This is the full list; the README keeps the few that change how you use the action day to day.

## Posture

- **`disable-sudo: false` or `docker: keep` makes enforce advisory.** Any step with root can
  remove the proxy and firewall, and docker group membership is root-equivalent. Both are
  removed by enforce; the summary labels the job ADVISORY when either was kept.
- **The job summary and the tamper check are advisory.** They come from the post step, which
  runs as the runner user from the action's files on the runner, and the job's own steps can
  modify those. A malicious step could alter or suppress the summary, the tamper check and
  `fail-on-tampering`. Treat them as a tripwire and a record, not tamper-proof evidence. The
  egress controls themselves (proxy, DNS, firewall, sudo and docker removal) are root-owned and
  don't depend on the post step. See [DESIGN-post-run-integrity.md](DESIGN-post-run-integrity.md).
- **Allowlisted hosts are full-capability channels.** If `github.com` is allowed, a malicious
  step can push data to a repository it controls. `allowed-domains` narrows egress to names; it
  can't judge what a request does. Use [`http-filter`](DESIGN-L7-path-method.md) to make a host
  read-only or to limit its writes to named paths.

## Names and DNS

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
  without their length. Every label is checked, the domain and TLD included. This keeps obviously
  encoded values out of the report, but it is **not a guarantee**: short or word-like labels are
  caught only part of the time, so a step that shapes its data to avoid the filter can get an
  **entire** secret into the summary and job log in recoverable form, even through a single
  refused hostname. Treat the summary of a job that ran untrusted code as able to contain
  anything that code could read. The raw logs on the runner (`/var/log/safer-runner/`, including
  `proxy-flows.jsonl`) are **not** redacted: don't upload them as artifacts from a public repository.
- **No DNS-rebinding protection for clients outside the proxy.** The resolver returns internal
  answers as-is; the proxy refuses them for all proxied traffic. A process that dials a
  loopback, docker-bridge or IMDS address by name gets no more than it could by IP literal
  (those addresses are reachable directly by design), but a browser-style rebinding attack on a
  local service inside the job is not prevented.

## Protocol and transport

- **Only TCP 80/443 is proxied.** In enforce, other ports are rejected, including SSH
  (`git@github.com`).
- **IPv6 container networks** are rejected in enforce (there is no IPv6 path through the proxy).
- **Clients that pin certificates, or that ignore both the system store and the exported CA
  variables, fail** on allowlisted hosts. Fix: add the host to `passthrough-domains`, but only if
  it is single-tenant.
- **JDKs installed after this action** (for example by `actions/setup-java`) don't get the CA
  imported.
- **Throughput:** about 140–160 MiB/s per job through TLS interception, because the proxy is
  single-core.

## Containers

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
  `docker: keep` for such jobs (docker is then root-equivalent, see above). `analyze` lists
  them among the docker use enforce would block. The runner's end-of-job cleanup of service
  containers also logs a harmless permission warning.
- **`analyze`'s docker evaluation is best effort.** It records `docker events` from setup on;
  the job has docker in analyze, so it can stop the recording (the summary then says the
  recording was partial). Read-only docker calls (`docker ps`, `logs`, `inspect`, `info`,
  `login`) leave no event and are not seen, so a job whose only docker use is, say, `docker logs`
  in a failure step can still break under enforce. Docker outside the runner's dockerd (rootless
  docker, podman) is not seen, and a step's `docker exec` of exactly a container's healthcheck
  command is taken for the healthcheck.
- **`docker build`**: RUN steps get container-path filtering; allowlisted HTTPS works by
  SNI without a CA. To intercept inside a build, `COPY` or secret-mount the CA yourself.

## Platform

- Linux (Ubuntu 24.04 / 26.04) GitHub-hosted runners only.
