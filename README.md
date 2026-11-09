# Safer Runner Action

![Safer Runner Action — hostname-based egress control for GitHub Actions runners](docs/assets/banner.svg)

Safer Runner limits the hosts that a GitHub Actions job can connect to.

A GitHub-hosted runner can reach the whole internet. If a dependency, an action or a build script
is compromised, it can send your source code, tokens and secrets anywhere. Safer Runner blocks
all outbound traffic except to GitHub's own hosts and the hostnames that you allow. It also
removes `sudo` and `docker` access, so that a step cannot switch the controls off.

The action checks the hostname, not the IP address. Allowed IP addresses often belong to shared
CDNs and cloud ranges, so an IP allowlist also lets traffic through to an attacker's site on the
same range. [How it works](docs/HOW-IT-WORKS.md) explains the design.

An allowed host is still a way out: a step can `npm publish` or `git push` your secrets to it.
With `http-filter`, the action also checks the method and path of each request to the hosts that
you name. For example, a job can install from npm but not publish, or push only to your own
repositories.

Safer Runner runs on GitHub-hosted Ubuntu 24.04 and 26.04 runners.

## Get started

Start in `analyze` mode. Safer Runner records what the job does and suggests a configuration. Then
change to `enforce` mode, which blocks everything that the configuration does not allow.

1. Add the action as the **first** step of the job:

   ```yaml
   jobs:
     build:
       runs-on: ubuntu-latest
       steps:
         - uses: portswigger-tim/safer-runner-action@9874c0f024d1dff1e137c2c687c04b954287b498 # v2.4.0
         - uses: actions/checkout@v5 # pin this by SHA too
         - run: npm ci
   ```

   The action's `pre` step applies the controls before any other step runs, including the `pre`
   steps of other actions. Pin the action to a commit SHA, as shown.
   [Verifying this action](docs/VERIFYING.md) explains why, and how to check a release.

2. Run the workflow. `analyze` is the default mode, which does not block hosts.

3. Open the job summary of the run. The **Summary** section shows what `enforce` would block. The
   **Suggested Enforce Configuration** section contains a `uses:` block with the settings that
   this job needs.

4. Review the suggestion, and copy it into the workflow. Below it, the section **Optional: narrow
   the allowed hosts further with `http-filter`** suggests the methods and paths that the job used
   on each host. Add that too, to block the writes that the job does not need. The step then looks
   like this:

   ```yaml
         - uses: portswigger-tim/safer-runner-action@9874c0f024d1dff1e137c2c687c04b954287b498 # v2.4.0
           with:
             mode: enforce
             allowed-domains: |
               registry.npmjs.org
             http-filter: |
               registry.npmjs.org:
                 "*": GET, HEAD
   ```

   The `http-filter` makes `registry.npmjs.org` read-only: `npm ci` can install packages, but
   `npm publish` is blocked. [Limit methods and paths on a host](docs/HTTP-FILTER.md) shows more
   examples, such as allowing `git push` only to your own repositories.

   You do not need to allow GitHub's own hosts (checkout, artifacts, cache and OIDC). The action
   allows them automatically.

5. Run the workflow again. If the job fails because a host is blocked, the job summary shows the
   host. [Troubleshooting](docs/TROUBLESHOOTING.md) tells you what to do.

In `enforce` mode, the action also removes `sudo` and `docker` access from the job. If the job
needs them, the suggestion includes `sudo-config` or `docker: keep`, and the job is
[ADVISORY](docs/CONFIGURATION.md#privilege-sudo-and-docker).

## Documentation

### How-to guides

- [Troubleshooting](docs/TROUBLESHOOTING.md): find why a request was blocked, and fix it.
- [Limit methods and paths on a host](docs/HTTP-FILTER.md): make a registry read-only, allow
  `git push` only to your own repositories, or build a filter from the job's traffic.
- [Verifying this action](docs/VERIFYING.md): pin the action by SHA and check its build
  provenance.

### Reference

- [Configuration](docs/CONFIGURATION.md): every input, the allowlist syntax, and the sudo and
  docker options.
- [`http-filter` rules](docs/HTTP-FILTER.md#rules): the path and method syntax, and the GitHub
  platform endpoints.
- [Limitations](docs/LIMITATIONS.md): what the action does not control.
- [Release notes](docs/RELEASE-NOTES.md)

### Explanation

- [How it works](docs/HOW-IT-WORKS.md): the threat model, the four layers of control, and the
  job lifecycle.
- [CI/CD good practice](docs/CICD-GOOD-PRACTICE.md): other controls to use with this action.

To report a vulnerability, read the [security policy](SECURITY.md).
