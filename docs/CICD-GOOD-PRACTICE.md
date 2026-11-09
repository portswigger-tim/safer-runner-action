# CI/CD good practice

Safer Runner limits where a compromised step can send data. The practices on this page make it
less likely that a hostile step runs at all, and limit what it can take if it does. Most of them
cost nothing. They are most important on public repositories, where a pull request or a
dependency can run an attacker's code.

Use them with the action, not in place of it.

## Control what runs

- **Pin actions to a full commit SHA, not a tag.** A tag can be moved to different code, for
  example by an attacker who steals a maintainer's account. The tj-actions/changed-files
  compromise worked like this. Put the version in a comment so that Dependabot or Renovate can
  update the SHA. [Verifying this action](VERIFYING.md) shows how to do this for Safer Runner.
- **Pin the rest of the toolchain.** Use lockfiles with integrity hashes (`npm ci`,
  `pip --require-hashes`), and pin base images by digest. Do not use `curl | bash` installers:
  vendor or pin what they download.
- **Do not run install scripts that you do not need** (`npm ci --ignore-scripts`). The Shai-Hulud
  npm worm ran from install scripts.
- **Protect the files that control the pipeline.** Workflows, `action.yaml`, Dockerfiles, build
  and release scripts, and hook configuration such as `.pre-commit-config.yaml` all run code,
  often before your tests and sometimes with network access. Require CODEOWNERS review for
  changes to them. A pull request that changes the pipeline can turn off every other control.
- **Use `pull_request`, not `pull_request_target`, for pull requests from forks,** and require
  approval for external contributors. Never check out and run the code of a pull request in a
  job that has secrets or a write token.
- **Keep CI small.** Fewer actions, permissions and network destinations give a smaller attack
  surface, and an allowlist that you can understand.

## Limit what a compromised step can reach

- **Give `GITHUB_TOKEN` the least privilege.** Set the workflow's default `permissions:` to
  `contents: read`, and give each job only the permissions that it needs.
- **Keep secrets out of jobs that run untrusted code.** A job that has a secret can leak it
  through any dependency that it runs.
- **Separate the untrusted build from the trusted release.** Build and test in a job with low
  privilege, no secrets and Safer Runner in `enforce` mode. Give the artifact, checked by digest,
  to a separate job that signs and publishes it.
- **Put publish and deploy jobs behind a protected
  [environment](https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment)**
  with required reviewers.
- **Use short-lived credentials (OIDC) in place of stored secrets.** Exchange the job's GitHub
  OIDC token for cloud credentials, and limit the cloud trust policy to the protected environment.
  Give each credential access to the smallest set of repositories, registries or paths. A
  credential that expires in minutes and reaches one resource has little value to an attacker.
- **Do not share caches between untrusted jobs and release jobs.** A pull request can put
  malicious content in a shared cache. Use separate cache keys, or no cache, for jobs that
  publish.

## Limit where data can go

- **Use Safer Runner in `enforce` mode,** with exact hostnames in place of wildcards where you can.
  Read the job summary after each run to find new or unexpected destinations.
- **Do not treat logs or build output as a security boundary.** A hostile step can read anything
  in the job, encode it, and print it past log masking. Keep sensitive data out of jobs that run
  untrusted code. For the same reason, Safer Runner's own job summary is advisory.

## Find problems early

Turn on secret scanning with push protection, and Dependabot. They cost little, and they find
common problems early.

Publish build provenance attestations for your own artifacts. The users of your artifacts can
then check them with `gh attestation verify`.
