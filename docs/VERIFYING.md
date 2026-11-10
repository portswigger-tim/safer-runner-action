# Verifying this action

The action's `pre` step uses `sudo` to install binaries and change the runner's configuration as
root. A tampered release could take control of your runner. Treat the action as you would any
other privileged dependency.

## Pin the action to a commit SHA

Use the full commit SHA, not a tag or a branch: tags can be moved. There is no `@v2` tag that
moves to new releases. Put the version in a comment, so that Dependabot or Renovate can update
the SHA:

```yaml
- uses: portswigger-tim/safer-runner-action@e7a4410b8713de3759dae8997ee1c0223863bba9 # v2.5.2
```

## Check the build provenance

Each release made by the [release workflow](../.github/workflows/release.yml) has a signed
[build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
for `action.yaml`, `dist/**`, `proxy/policy.py` and `proxy/policy_core.py`, the files that setup
runs and installs as root. The workflow makes the attestation only after it checks that:

- the tag is on a release branch,
- the tests pass, and
- a clean build of `dist/` from the tagged source is identical to the `dist/` in the commit.

Releases before the release workflow have no attestation. The post step also runs
`proxy/suggest.py` and `proxy/sudo_suggest.py`, which have no attestation. Pinning the commit SHA
fixes their content.

To check the commit that you pin:

```bash
REPO=portswigger-tim/safer-runner-action
SHA=<the commit you pin>
git clone --quiet https://github.com/$REPO && cd safer-runner-action && git checkout --quiet "$SHA"
for f in action.yaml dist/*/index.js proxy/policy.py proxy/policy_core.py; do
  gh attestation verify "$f" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release.yml" \
    --source-digest "$SHA" --deny-self-hosted-runners || echo "NOT VERIFIED: $f"
done
```

A passing check shows that this repository's release workflow built and checked those files from
that commit. It does not show that the source is safe. If a new release has no attestation, or
the check fails, do not use the release, and [report it](../SECURITY.md).

[CI/CD good practice](CICD-GOOD-PRACTICE.md) describes other controls to use with this action.
