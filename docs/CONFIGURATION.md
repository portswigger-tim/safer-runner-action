# Configuration

All inputs are optional. With no inputs, the action runs in `analyze` mode and does not block
hosts.

| Input | Default | Summary |
|---|---|---|
| [`mode`](#mode) | `analyze` | `analyze` records and reports. `enforce` blocks. |
| [`allowed-domains`](#allowed-domains) | none | The hostnames the job can connect to, in addition to GitHub's own. |
| [`passthrough-domains`](#passthrough-domains) | `hosted-compute-*.githubapp.com` | Hosts that the proxy checks by name only and does not decrypt. |
| [`block-risky-github-subdomains`](#block-risky-github-subdomains) | `true` | Block GitHub hosts that serve any user's content. |
| [`dns-servers`](#dns-servers) | `9.9.9.9 149.112.112.112` | The DNS servers that resolve allowed names. |
| [`http-filter`](#http-filter-and-allow-github-platform) | none | The methods and paths allowed on a host. |
| [`allow-github-platform`](#http-filter-and-allow-github-platform) | `true` | Allow the GitHub platform's own endpoints on a filtered host. |
| [`disable-sudo`](#disable-sudo) | `true` | Remove `sudo` from the job. |
| [`sudo-config`](#sudo-config) | none | The exact `sudo` commands that the job can still run. |
| [`docker`](#docker) | `remove-group` | `keep`, `remove-group` or `stop`. |
| [`fail-on-tampering`](#fail-on-tampering) | follows `mode` | Fail the job if its security configuration changed during the run. |

## Operating mode

### `mode`

- `analyze` sends all HTTP and HTTPS through the proxy and records it, but does not block hosts.
  The job summary shows what `enforce` would block, and suggests the inputs for `enforce`.
- `enforce` blocks all traffic to hosts that are not allowed, and applies all the other inputs.

In `analyze` mode, the action evaluates `block-risky-github-subdomains`, `http-filter`,
`disable-sudo`, `sudo-config` and `docker`, but does not apply them. The network inputs
(`allowed-domains`, `passthrough-domains` and `dns-servers`) apply in both modes.

## Network

### `allowed-domains`

The hostnames that the job can connect to, separated by spaces, commas or new lines. You do not
need to list GitHub's own hosts: the action gets them from `api.github.com/meta` and always
allows them.

| Entry | Allows |
|---|---|
| `example.com` | only `example.com`, not `www.example.com` |
| `*.example.com` | all subdomains, at any depth, but not `example.com` |
| `.example.com` | `example.com` and all its subdomains |
| `pre*.example.com` | names in which `*` matches within one label, such as `prefix-1.example.com` |

Use exact names where you can. A wildcard entry is a DNS channel to its zone, and a wildcard on a
zone where anyone can get a name allows anyone's server
([Limitations](LIMITATIONS.md#allowed-hosts)).

The action ignores entries for these shared domains, with or without a wildcard, and writes a
warning: `windows.net`, `core.windows.net`, `blob.core.windows.net`, `blob.storage.azure.net`,
`githubusercontent.com`, `amazonaws.com` and `s3.amazonaws.com`. It does not detect other shared
domains, such as `cloudfront.net` or `azurewebsites.net`. Never put a wildcard on a domain where
anyone can get a name.

### `passthrough-domains`

Hosts that the proxy checks by name (TLS SNI) only. The proxy does not decrypt their traffic, so
it cannot check the `Host` header or apply `http-filter`. Use this input only for a single-tenant
host whose client cannot trust the action's CA, for example a client that pins certificates.

`hosted-compute-*.githubapp.com` is always included. The runner's own agent starts before the
action and cannot trust a CA that is added later.

### `block-risky-github-subdomains`

When `true`, `enforce` blocks `gist.github.com`, `gist.githubusercontent.com` and
`raw.githubusercontent.com`, even when a wildcard such as `*.github.com` or one of your entries
covers them. Any GitHub user can publish content on these hosts, and attackers have used them to
serve malicious scripts. This narrows downloads from GitHub, but does not stop them: GitHub's
always-allowed hosts still serve any public repository, release asset and container image.

### `dns-servers`

The upstream DNS servers that the resolver sends allowed names to: IP addresses, separated by
spaces, commas or new lines. The resolver tries them in order. The default is Quad9. An empty
value uses the default.

### `http-filter` and `allow-github-platform`

`http-filter` allows only the methods and paths that you list on a host that is already allowed.
For example, it can make a package registry read-only. `allow-github-platform` keeps the GitHub
Actions platform working on a filtered GitHub host. [Limit methods and paths on a
host](HTTP-FILTER.md) explains both inputs, and lists [the rules](HTTP-FILTER.md#rules).

## Privilege: `sudo` and `docker`

A step with root access can remove the proxy and the firewall rules. Membership of the `docker`
group gives root access too. In `enforce` mode, the action therefore removes both from the
runner user by default.

If you keep either one, the job summary labels the job **ADVISORY**. The action still applies
all its controls, but they are not a security boundary, because a step can remove them.

In `analyze` mode, the action does not change `sudo` or `docker`. The job summary lists the
`sudo` commands and the docker use that `enforce` would block, and suggests a `sudo-config` and a
`docker` setting. This evaluation is best effort: [Limitations](LIMITATIONS.md#the-analyze-evaluation-of-sudo-and-docker)
lists what it cannot see.

### `disable-sudo`

- `true` (the default): `enforce` removes `sudo` from the runner user after setup. The action
  keeps only its own read-only checks, and any commands in `sudo-config`.
- `false`: the job keeps full `sudo`. `enforce` is **ADVISORY**.

### `sudo-config`

The exact `sudo` commands that the job can still run as root when `disable-sudo` is `true`, as a
YAML list:

```yaml
- uses: portswigger-tim/safer-runner-action@<sha> # vX.Y.Z
  with:
    mode: enforce
    sudo-config: |
      - /usr/bin/apt-get update
      - /usr/bin/apt-get install -y jq
```

- Each entry is an absolute path and its exact arguments. An entry with no arguments allows no
  arguments.
- A trailing `*` allows one or more further arguments, including options. Name at least one
  argument before the `*`. Avoid `*` if you can.
- Entries can contain only letters, digits and `_ . / @ + -`.
- The commands run as root. `sudo -u <user>` is not supported.
- `sudo-config` with `disable-sudo: false` is an error.

Any `sudo-config` makes `enforce` **ADVISORY**. Many commands can run other code or write files
(for example `apt-get`, `bash`, `tee` and `systemctl`), and thus give the job root access. Setup
writes a warning for each entry that gives root access, or that is under a directory the job can
write to (such as `/home`, `/tmp`, the tool cache or the workspace).

The suggested `sudo-config` contains exact lines only. It leaves out commands run as another user,
and lines with arguments that look like secrets.

### `docker`

- `remove-group` (the default): `enforce` removes the runner user from the `docker` group and
  makes the docker socket accessible to root only. Service containers continue to run.
- `stop`: `enforce` stops and disables the docker daemon, which also stops its containers.
- `keep`: the job keeps `docker` access. `enforce` is **ADVISORY**.

In `enforce` mode, the action checks that the change took effect. If it did not, setup fails.

A job whose steps run docker commands, or that uses a docker container action, needs
`docker: keep`. If you can, move that work to a job that does not need `enforce` mode.

## Tamper check

### `fail-on-tampering`

The post step compares the action's configuration files and firewall rules with the checksums
recorded at setup ([How it works](HOW-IT-WORKS.md#the-job-lifecycle)). `fail-on-tampering`
decides what happens when they changed, or when the setup record is missing or cannot be read:

- unset (the default): fail the job in `enforce` mode, and only report the change in `analyze`
  mode.
- `true`: fail the job in both modes.
- `false`: only report the change.

This check is a tripwire, not proof. [Limitations](LIMITATIONS.md#the-job-summary-and-the-tamper-check)
explains why.
