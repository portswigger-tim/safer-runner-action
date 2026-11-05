# Security policy

Safer Runner runs with root on the runner (its `pre` step installs and configures the proxy,
DNS resolver and firewall), so a flaw in it, or in how it is built and released, can affect
every workflow that uses it. Please report problems privately.

## Reporting a vulnerability

Report it through **GitHub's private vulnerability reporting**: the repository's
**Security** tab → **Report a vulnerability**
(<https://github.com/portswigger-tim/safer-runner-action/security/advisories/new>).
That opens a private advisory only the maintainers can see.

Please:

- **Don't** open a public issue, pull request, discussion or comment about it, and don't
  publish a proof of concept, until a fix has been released and you've agreed a date with us.
- Include the action version (tag or commit SHA), runner image (e.g. `ubuntu-24.04`), the
  inputs you used, and the steps or a minimal workflow that shows the problem.
- Tell us whether you'd like to be credited.

If the **Report a vulnerability** button isn't available, open an issue that says only that you
have a security report and need a private contact. Put no details in it.

## What to expect

- An acknowledgement within 5 working days, and an initial assessment after that.
- Fixes ship as ordinary releases. Release notes describe security fixes in general terms
  ("hardening") and don't include exploit details. We don't normally publish a separate
  advisory or request a CVE; if you need one, say so in the report and we'll discuss it.
- We'll agree any public write-up with you, after users have had a reasonable time to update.

## Supported versions

| Version            | Supported                    |
| ------------------ | ---------------------------- |
| v2 (latest beta)   | Yes                          |
| v1 (latest v1.x.y) | Yes, security fixes          |
| Older tags         | No - update to the latest    |

## In scope

- Ways for workflow code to bypass or silently disable enforce mode (egress allowed that
  should be blocked, regaining sudo/docker when they were removed, forging the report or the
  tampering check).
- Ways for the action itself to weaken the runner (e.g. files or services it leaves writable).
- The build and release path: anything that would let a release contain code that isn't in
  this repository's reviewed source.

Known, documented limitations (see "Limitations" in the [README](README.md)), such as
exfiltration through domains you have allowlisted, are not vulnerabilities on their own.

## Verifying releases

See [Verifying this action](README.md#verifying-this-action-supply-chain) in the README.
