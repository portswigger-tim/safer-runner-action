# Troubleshooting

Start with the job summary of the failed run. Its **Blocked** table has one row for each thing
the action blocked. The **Reason** column is the word the action's log wrote, so you can search
the logs for it. Find the reason below.

If you are not sure what the job needs, run it in `analyze` mode, and use the suggested
configuration.

## A host is blocked

### `sni-not-allowed` or `host-not-allowed`

The host is not on the allowlist.

1. Make sure that the job must connect to this host. An unknown host can be a sign of a
   compromised dependency.
2. Add the host to `allowed-domains`. The job summary shows the lines to add under **To allow
   what was blocked**. An entry allows only that exact name: `example.com` does not allow
   `www.example.com`. [Configuration](CONFIGURATION.md#allowed-domains) shows the wildcard forms.

### `BLOCK` in the `dns` layer

The job looked up a name that is not on the allowlist, and did not connect to it. If the job needs
the name, add it to `allowed-domains`. In `analyze` mode the reason is `WOULD_BLOCK`.

### `sni-denied` or `host-denied`

The host is on the risky-subdomain denylist: `gist.github.com`, `gist.githubusercontent.com` or
`raw.githubusercontent.com`. Adding it to `allowed-domains` does not help: the denylist takes
priority. Do one of these:

- Download the file from a release asset, or keep a copy of it in your repository.
- Set `block-risky-github-subdomains: false`.

### `upstream-unresolved`

The name does not exist in DNS, so the action sent nothing. Correct the name in the job.

### `host-sni-mismatch` or `upstream-ip-forbidden`

These are attempts to get round the proxy, and the **Blocked** table lists them first:

- `host-sni-mismatch`: a request inside a TLS connection asked for a different host than the TLS
  connection (domain fronting). The row shows the TLS name and the address the client dialled.
- `upstream-ip-forbidden`: an allowed name resolved to an internal address, such as the cloud
  metadata service. The row shows the address.

A normal build does not do these things. Examine the steps that ran, and the dependencies they
installed. Do not try to allow these connections.

Runners with Azure private networking that reach private services by name also show
`upstream-ip-forbidden`. You cannot allow such names
([Limitations](LIMITATIONS.md#names-and-addresses)).

### `no-sni`, `ip-literal-sni` or `ip-literal-host`

The client connected to an IP address, not to a hostname. The action cannot check such a
connection, so you cannot allow it. Change the client to use a hostname.

## A request is blocked by `http-filter`

The reason is `path-not-allowed` or `method-not-allowed`, in the `http-filter` layer. The row
shows the host and the method. It does not show the path, because the path can carry data.

1. Run the job in `analyze` mode without that host's `http-filter` entry.
2. Find the host in the suggested `http-filter`, and review the rule. A write rule is how data
   leaves the job.
3. Add the rule to `http-filter`.

## A connection on another port is blocked

The reason is `Drop`, in the `firewall` layer (`CDrop` for a container). In `enforce` mode, only
ports 80 and 443 are allowed. Change the client to use HTTPS, for example
`https://github.com/...` in place of `git@github.com:...`.

## A client fails with a TLS certificate error

The client does not trust the action's CA. [How it works](HOW-IT-WORKS.md#the-ca-and-client-trust)
lists where the action installs the CA.

1. Make the client use the system CA store, or one of the exported variables, for example
   `SSL_CERT_FILE`.
2. If you cannot, and the host is single-tenant, add it to `passthrough-domains`. The proxy then
   checks the host by name only and does not decrypt it.

### Java

A JDK that a step downloads after setup, for example a Zulu or Corretto JDK from
`actions/setup-java`, does not trust the CA. Add a step after `actions/setup-java` that imports
it. The step does nothing if the JDK already trusts the CA:

```yaml
- run: |
    ks="$JAVA_HOME/lib/security/cacerts"
    [ -f "$ks" ] || ks="$JAVA_HOME/jre/lib/security/cacerts"   # JDK 8
    keytool -list -keystore "$ks" -storepass changeit -alias safer-runner-ca >/dev/null 2>&1 ||
      keytool -importcert -noprompt -keystore "$ks" -storepass changeit \
        -alias safer-runner-ca -file /etc/safer-runner/ca.pem
```

## A `sudo` command fails

In `enforce` mode, the action removes `sudo`, and `sudo` refuses the command. The reason is
`disable-sudo`, or `sudo-config` when the job keeps some command lines. Do one of these:

- Change the step so that it does not need `sudo`.
- Run the job in `analyze` mode, and add the suggested `sudo-config`. The job is then ADVISORY.

## A `docker` command fails with "permission denied"

In `enforce` mode, the action removes docker access. A step that runs `docker`, or a docker
container action, then fails. Move the docker work to another job, or set `docker: keep`. The
job is then ADVISORY.

## Setup fails

- **An input is not valid.** The action parses `http-filter` and `sudo-config` strictly. The error
  in the step log names the problem. [Configuration](CONFIGURATION.md) shows the correct form.
- **The job uses `container:`.** Job containers are not supported. Run the job on the runner, and
  start containers with `services:` or `docker run`.
- **Setup could not download a pinned binary.** A download failed after several tries, for
  example because of a temporary GitHub or upstream error. Run the job again.

## The post step reports tampering

The action's configuration files or firewall rules changed during the job. In `enforce` mode, the
job fails. The job summary shows **tamper check: CHANGED**, and its **Safer Runner** part names
what changed. Examine the steps that ran: a normal build does not change these files.

## Read the logs on the runner

The action writes its logs to `/var/log/safer-runner/`. The runner user can read them without
`sudo`.

| File | Contents |
|---|---|
| `proxy-flows.jsonl` | One JSON line for each proxy decision, with the reason. |
| `dns.log` | One line for each DNS query: `ALLOW`, `BLOCK` or `WOULD_BLOCK`. |
| `firewall.log` | Connections that the firewall recorded or blocked. |
| `sudo.log` | `sudo` use. |
| `selftest.json` | The results of the setup self-tests. |

These logs are not redacted. A blocked name or path can contain the data that a step tried to
send out. Do not print them in the job log, or upload them as an artifact, from a public
repository.

To print a count of the block reasons, without names or paths:

```yaml
- if: failure()
  run: jq -r 'select(.verdict == "BLOCK") | .reason' /var/log/safer-runner/proxy-flows.jsonl | sort | uniq -c
```

The count includes the blocks from the setup self-tests. In `analyze` mode, use
`"WOULD_BLOCK"`.
