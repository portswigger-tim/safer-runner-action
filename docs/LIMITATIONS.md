# Limitations

Safer Runner controls one thing: the network destinations a job can reach. It is not a complete
sandbox. This page lists what it does not control, and where its results are best effort.

## Privilege

- **A step with root access can remove every control.** In `enforce` mode, the action removes
  `sudo` and `docker` access for this reason. If you keep either, with `disable-sudo: false`,
  any `sudo-config` entry or `docker: keep`, the job is
  [ADVISORY](CONFIGURATION.md#privilege-sudo-and-docker).
- **Do not set `continue-on-error` on the action's step.** If setup fails in `enforce` mode, the
  job must stop. With `continue-on-error`, the job continues without some or all of the controls.

## Allowed hosts

- **GitHub's own hosts are always allowed.** The action always allows `github.com`,
  `*.github.com` (including `api.github.com`), `ghcr.io`, the Actions service hosts, and the
  storage that artifacts and caches use. No input removes them. A step can therefore always send
  data out through GitHub: a `git push` to a repository it controls, API writes with a token, an
  artifact, a cache entry, or the job log, which is public on a public repository. Use
  [`http-filter`](HTTP-FILTER.md) on `github.com` and `api.github.com`, and give `GITHUB_TOKEN`
  the least privilege.
- **Every allowed host is a full-capability channel.** `allowed-domains` limits where a job
  connects, not what it does there. `http-filter` can make a host read-only, or limit its writes
  to named paths. Its own limits are on its page.
- **A wildcard entry is a DNS channel.** For `*.example.com`, the resolver forwards every lookup
  under the zone, so whoever runs the zone's name servers sees `<anything>.example.com`. Exact
  entries do not have this problem.
- **A wildcard on a zone where anyone can get a name allows anyone's server.** For example,
  `*.nip.io` allows every public IP address, because `1-2-3-4.nip.io` resolves to `1.2.3.4`. The
  action ignores only a fixed list of shared domains (see
  [`allowed-domains`](CONFIGURATION.md#allowed-domains)).
- **Passthrough hosts are checked by name only.** The proxy does not decrypt them, so it cannot
  check the `Host` header. A client can reach another site on the same front end as a passthrough
  host (domain fronting). Use `passthrough-domains` only for single-tenant hosts.

## Names and addresses

- **The proxy blocks allowed names that resolve to internal addresses** (loopback, link-local,
  private and CGNAT ranges). This includes runners with Azure private networking that reach
  private services by name. You cannot allow such names in `enforce` mode.
- **The runner can always reach two Azure platform addresses.** The firewall lets traffic to the
  instance metadata service (`169.254.169.254`) and the Azure wireserver (`168.63.129.16`)
  through, because the runner needs them.
- **There is no DNS-rebinding protection outside the proxy.** The resolver returns internal
  addresses unchanged, and the proxy blocks them for all proxied traffic. A process that connects
  by name to a loopback, docker bridge or Azure platform address gets nothing more than it could
  get by IP address. But a browser-style rebinding attack on a local service inside the job is not
  prevented.

## Protocols and clients

- **Only TCP ports 80 and 443 go through the proxy.** In `enforce` mode, the firewall blocks
  all other ports, including SSH (`git@github.com`). In both modes, it blocks QUIC (UDP port 443),
  so clients fall back to TCP.
- **There is no IPv6 path through the proxy.** In `enforce` mode, the firewall blocks IPv6,
  including IPv6 container networks.
- **A client that pins certificates, or ignores both the system CA store and the exported CA
  variables, fails on allowed hosts.** Add the host to `passthrough-domains` if it is
  single-tenant.
- **The action adds its CA only to the JDKs that it finds at setup,** from `JAVA_HOME` and the
  `JAVA_HOME_<version>_<arch>` variables of the runner image. A JDK that a later step downloads
  (for example a Zulu or Corretto JDK from `actions/setup-java`) does not trust the CA.
  [Troubleshooting](TROUBLESHOOTING.md#a-client-fails-with-a-tls-certificate-error) shows how to
  add it.
- **Throughput through the proxy is about 140–160 MiB/s per job,** because the proxy uses one
  CPU core to decrypt and encrypt TLS.

## Containers

- **Containers are a boundary only when docker access is removed,** as `enforce` does by default.
  With `docker: keep`, a step can run `docker run --privileged --network host` and bypass the
  controls. The container rules then protect against dependencies inside containers, but not
  against a determined step.
- **The proxy checks container HTTPS by name only (SNI).** Containers do not need the action's
  CA. But the proxy cannot check the `Host` header, so a container can reach another site on the
  same front end as an allowed host. This is the same trade-off as `passthrough-domains`.
  Container HTTPS shows no paths in the job summary, and `http-filter` does not apply to it.
- **Azure Storage is the exception.** The proxy decrypts container traffic to Azure Storage
  hosts and checks the `Host` header. A container that connects to an allowed storage account in
  `enforce` mode needs the CA (`/etc/safer-runner/ca.pem`), or must make the connection from a
  step on the runner.
- **Job containers (`container:`) are not supported.** The action would run inside the container
  and cannot control the runner. `enforce` fails with an explanation. `analyze` writes a warning
  and records nothing. Run the job on the runner, and use `services:` and `docker run` steps.
- **Docker container actions** (`uses: docker://…` and Dockerfile actions) do not run when
  `enforce` removes docker access, because the runner starts them as the runner user. They need
  `docker: keep`.
- **The runner's end-of-job clean-up of service containers writes a permission warning** when
  docker access is removed. You can ignore it.
- **`docker build` `RUN` steps go through the proxy,** and allowed HTTPS works by name without
  the CA. To decrypt traffic inside a build, `COPY` or secret-mount the CA yourself.

## The `analyze` evaluation of `sudo` and `docker`

- **The `sudo` evaluation is best effort.** The `sudo` log does not show `sudo -E`, or where one
  argument ends and the next starts. Check the suggested `sudo-config` in `enforce` mode before
  you rely on it.
- **The action tells its own `sudo` commands from the job's by the command line and by their
  position in the `sudo` log.** If a background process that the job started runs `sudo` while
  the post step runs, the job summary can count that command as the action's own.
- **The `docker` evaluation is best effort.**
  - It records `docker events` from setup onwards. In `analyze` mode the job has `docker`, so it
    can stop the recording. The job summary then says that the recording is partial.
  - Read-only calls (`docker ps`, `logs`, `inspect`, `info`, `login`) make no event, so the
    action does not see them. A job whose only docker use is, for example, `docker logs` in a
    failure step can still fail in `enforce` mode.
  - It does not see docker outside the runner's own daemon (rootless docker, podman).
  - It counts a step's `docker exec` of exactly a container's healthcheck command as the
    healthcheck.

## The job summary and the tamper check

- **The job summary and the tamper check are a record, not proof.** The post step that makes
  them runs as the runner user, from the action's files on the runner. The job's steps can change
  those files, so a malicious step could change or hide the job summary, the tamper check and
  `fail-on-tampering`. The controls themselves (proxy, DNS, firewall, `sudo` and `docker`
  removal) are owned by root and do not depend on the post step.
- **Redaction of blocked names is best effort.** A blocked name can carry the stolen data, for
  example `<base64 secret>.attacker.example`. The job summary and the job log replace each label
  that looks encoded with `‹redacted›`: runs of hex or digits of 6 or more characters, and
  base32 or base64-like labels of 8 or more (few vowels, digits spread through). This keeps
  obviously encoded values out. But a step that shapes its data to avoid the filter can still put
  a complete secret into the job summary. Treat the job summary of a job that ran untrusted code
  as able to contain anything that code could read.
- **Redaction of `sudo` arguments is best effort.** The job summary shows each `sudo` command with
  any argument that could be a credential replaced by `‹redacted›`. A credential that does not
  look like one can still show.
- **The suggested `allowed-domains` repeats your own entries.** In `analyze` mode, the
  suggestion keeps the job's current entries and adds the names that `enforce` would block. It
  leaves out an entry that looks like encoded data or a masked secret, with a comment that tells
  you to keep it. Any other entry is published in the job summary. An entry made from a secret
  shows as `***`: replace it by hand, because setup does not accept it as it is.
- **The logs on the runner are not redacted.** Do not print them in the job log, or upload them as
  an artifact, from a public repository.

## Platform

Safer Runner supports only GitHub-hosted Ubuntu 24.04 and 26.04 runners (amd64).
