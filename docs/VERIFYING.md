# Verifying this action (supply chain)

This action's `pre` step runs as root and installs root-owned binaries, so a tampered release
of it would own your runner. Treat it like any other privileged dependency.

## Pin it by full commit SHA

Not a tag or branch. Tags can be moved, and there is no moving `@v2` tag. Keep the version in a
comment so Dependabot or Renovate can update it:

```yaml
- uses: portswigger-tim/safer-runner-action@d9772c3c7c5c0f8cd6cb7123e138120b11c12371 # v2.2.1
```

## Check the build provenance

Check the provenance of the commit you pin. Releases from the
[release workflow](../.github/workflows/release.yml) onward carry a signed
[build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
for the files the runner executes (`action.yaml`, `dist/**`, `proxy/policy.py`,
`proxy/policy_core.py`). It is only produced after the release workflow has checked that the
tag is on a release branch, the tests pass, and a clean rebuild of `dist/` from the tagged
source is byte-identical to the committed `dist/`. Earlier tags have no attestation.

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

A passing check means those exact files were built and checked by this repository's release
workflow from that commit. It does not prove the source is safe, and a missing or failing
attestation on a new tag means: don't use it, and please [report it](../SECURITY.md).

## Run it alongside supply-chain-aware defaults

Safer Runner limits where a compromised dependency can send data; these limit what that
dependency can reach in the first place:

- Least-privilege `permissions:` at the top of every workflow (start from `contents: read`)
  and grant more per job.
- `npm ci --ignore-scripts` (and equivalents) where your build doesn't need install scripts.
- Don't share caches between untrusted jobs (PRs) and release/publish jobs: use distinct
  cache keys, or no cache, for anything that publishes.
- Put publish and deploy jobs that use OIDC (`id-token: write`) behind a protected
  [environment](https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment)
  with required reviewers, and scope the cloud-side trust policy to that environment.

For the wider picture — pinning actions by SHA, protecting the files that control the pipeline,
keeping secrets off public repos — see [CICD-GOOD-PRACTICE.md](CICD-GOOD-PRACTICE.md).
