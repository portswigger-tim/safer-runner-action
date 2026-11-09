# How it works

## The threat

Safer Runner protects against code that runs inside a job step: a compromised dependency, action
or build script. That code runs as the runner user. It can read the job's environment and try to
connect anywhere. It may also know that Safer Runner is present, and try to get around it.

The action limits where that code can send data. It does not limit what the code does on the
runner, or what it does on a host that is allowed. [Limitations](LIMITATIONS.md) lists what is out
of scope.

## Why hostnames, not IP addresses

An IP allowlist lets through every site on an allowed address range. Shared CDNs and cloud
platforms put many customers on the same addresses. A command such as
`curl --resolve attacker.example:443:<allowed-ip> https://attacker.example` then reaches an
attacker's site through an allowed address, with a valid certificate.

Safer Runner checks the hostname that the client asks for. It then connects to that hostname
itself, and ignores the IP address that the client chose. A spoofed address cannot get through.

## Four layers of control

### 1. The proxy

The proxy is the primary control. The firewall redirects all HTTP and HTTPS from the job to a
transparent mitmproxy, which decrypts TLS with the action's own CA. For each connection, the
proxy:

1. checks the TLS server name (SNI) against the allowlist, and blocks TLS with no server name
   or with an IP address as the name;
2. checks the `Host` header of each request against the allowlist, and checks that it matches
   the SNI, which stops domain fronting;
3. applies [`http-filter`](HTTP-FILTER.md), if you set it, to the method and path;
4. resolves the hostname itself and connects to it ("repoint"), and blocks the connection if the
   name resolves to an internal address.

The proxy does not decrypt hosts in `passthrough-domains`. It checks them by SNI only, but still
connects by name.

The proxy runs as its own user, in a systemd unit outside the job's processes. If it stops,
systemd restarts it.

### 2. DNS

A CoreDNS resolver answers only the allowed names, and returns NXDOMAIN for all other names. In
`enforce` mode, a lookup of a name that is not allowed never leaves the runner, which stops
most DNS tunnelling. A wildcard entry still lets lookups under its zone out
([Limitations](LIMITATIONS.md#allowed-hosts)).

The resolver and the proxy use the same allowlist patterns, so they always agree. DNS is a second
layer: the proxy makes the decision.

### 3. The firewall

iptables rules send ports 80 and 443 to the proxy, and all DNS traffic (port 53) to the resolver.
In `enforce` mode, the rules block all other traffic, including IPv6. The exceptions are loopback
and two Azure platform addresses that the runner needs. If the proxy stops, traffic has nowhere
else to go, so the firewall fails closed.

### 4. Privilege

A step with root access could remove the other three layers. In `enforce` mode, the action
therefore removes `sudo` and `docker` access from the runner user. Membership of the `docker`
group gives root access too. If you keep either, the job is
[ADVISORY](CONFIGURATION.md#privilege-sudo-and-docker).

## How container traffic is checked

Containers started with `services:`, `docker run`, docker compose or `docker build` go through
the same proxy and resolver. The proxy checks their HTTPS by name (SNI) only, so containers do
not need the action's CA.

## What analyze mode does

In `analyze` mode, the same layers run, but the action does not block hosts. The proxy passes a
host that `enforce` would block through by SNI, and records it. The resolver forwards every
name, and records the names that `enforce` would block. The post step then compares what the job
did with your inputs, and suggests a configuration for `enforce`.

## The CA and client trust

To read the `Host` header and the request path, the proxy decrypts TLS with a CA that the action
generates for each run. The private key stays in memory-backed storage (tmpfs). It is never
written to disk, and it is lost when the runner VM is destroyed.

Clients must trust the CA. The action adds it in three places:

- **The system CA store** (`/etc/ssl/certs/ca-certificates.crt`). This covers curl, wget, git,
  Python's `ssl` module, .NET, and all other clients that read the system store.
- **Environment variables** for all later steps, for clients such as Node.js that do not read the
  system store: `NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`,
  `SSL_CERT_FILE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE` and `CURL_CA_BUNDLE`.
- **The Java keystores** of the JDKs named by `JAVA_HOME` and the image's
  `JAVA_HOME_<version>_<arch>` variables.

The CA certificate is also at `/etc/safer-runner/ca.pem`, if you must give it to a container or
a tool yourself.

## The job lifecycle

The action has three steps.

1. **`pre`** applies all the controls before any other step runs, including the `pre` steps of
   other actions. At the end of setup, it runs live self-tests: it checks that an SNI block
   happens, that the proxy ignores the IP address a client chose, and that the resolver blocks a
   random subdomain of an exact entry. It also records a checksum of its configuration files and
   firewall rules. In `enforce` mode, any failure in setup fails the job.
2. **`main`** does nothing if `pre` completed. It runs setup only when `pre` did not run, for
   example in a local `uses: ./` action.
3. **`post`** compares the checksums with those recorded at setup, writes the job summary and
   applies [`fail-on-tampering`](CONFIGURATION.md#fail-on-tampering).

The proxy and the firewall stay active after `post`. The runner's own end-of-job traffic still
goes through them. GitHub then destroys the runner VM.
