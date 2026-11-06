# CI/CD good practice

Safer Runner hardens one layer — what a job can reach on the network. The practices below
reduce the chance a hostile step runs at all, or finds anything worth taking. Most cost
nothing, and they matter most on public repositories, where a pull request or a dependency
can run attacker-controlled code.

They are defence in depth. Use them alongside the action, not instead of it.

1. **Pin actions to a full commit SHA, not a tag.** Tags move. A stolen maintainer account or
   a repointed tag changes what runs without changing your workflow — the shape of the
   tj-actions/changed-files compromise. Keep `# vX.Y.Z` in a comment so Dependabot or Renovate
   can bump the SHA for you.

2. **Give `GITHUB_TOKEN` least privilege.** Default the workflow token to read-only, then grant
   `permissions:` per job — only what that job needs. A compromised step can do no more than the
   token allows.

3. **Keep secrets out of jobs that run untrusted code — and off public repos where you can.**
   Put credentialed steps (publish, deploy, sign) in a separate private repository, or in a
   protected environment with required reviewers, and trigger them from the public build with
   `workflow_run`. A public job that holds a secret can leak it through any dependency it runs.

4. **Separate "build untrusted" from "release trusted."** Build and test in a low-privilege,
   egress-hardened job with no secrets. Hand the artifact — verified by digest — to a separate
   job that signs and publishes with credentials and required approvals.

5. **Protect the files that control the pipeline.** Workflows, `action.yaml`/`Dockerfile`,
   build and release scripts, and hook configs such as `.pre-commit-config.yaml` all run code,
   often before your tests and sometimes with network access. Require CODEOWNERS review for
   changes to them. A pull request that edits the pipeline can switch off every other control.

6. **Use `pull_request`, not `pull_request_target`, for fork pull requests; require approval
   for external contributors.** Untrusted pull-request code should run with no secrets and no
   write token. Never check out and execute pull-request-head code in a privileged context.

7. **Pin and verify the whole toolchain, not just actions.** Use lockfiles with integrity
   hashes (`npm ci`, `pip --require-hashes`), pin base images by digest, and skip install
   lifecycle scripts where you do not need them (`npm ci --ignore-scripts`) — the route the
   Shai-Hulud npm worm used to phone home.

8. **Prefer short-lived, scoped credentials (OIDC) over stored secrets.** Exchange a GitHub
   OIDC token for per-job cloud credentials instead of long-lived keys, and scope every token
   to the minimum repository, registry or path. A credential that expires in minutes and
   reaches one resource is worth little if it is stolen.

9. **Do not treat logs or build output as a security boundary.** Assume a hostile step can read
   anything in the job and print it — encoded — past log masking. Keep anything genuinely
   sensitive out of jobs that run untrusted code. (Safer Runner's own post-run report and
   redaction are advisory for the same reason.)

10. **Keep CI minimal on public repos.** Fewer actions, permissions and network destinations
    mean a smaller attack surface and an allowlist you can reason about. Avoid `curl | bash`
    installers; vendor or pin what they fetch.

11. **Turn on the platform's supply-chain tripwires.** Secret scanning with push protection,
    Dependabot, and build provenance / attestation (so consumers can `gh attestation verify`
    your artifacts). They are cheap and catch the common failures early.

12. **Harden egress, then watch it.** Run Safer Runner in `analyze` to learn the real
    allowlist, then switch to `enforce`. Prefer exact names over `*.zone` wildcards — a wildcard
    is a DNS channel to the whole zone — and read the egress report after runs to spot new or
    unexpected destinations.

---

See the main [README](../README.md) for how to configure the action, and
[Limitations](LIMITATIONS.md) for what it does and does not cover.
