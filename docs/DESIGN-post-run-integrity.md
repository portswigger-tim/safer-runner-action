# Post-run integrity: from advisory tripwire to verifiable evidence

Status: **proposal, not implemented.** Today the post-run report and tamper check are advisory,
and the README, `action.yaml` and the job summary say so.

## Where things stand

The post step builds the job summary, runs the config tamper check against the root-owned
baseline, applies `fail-on-tampering` and destroys the CA key. The runner starts it the way it
starts any action step:

- it runs as the runner user,
- from the action's checkout on the runner,
- with the runner's own Node runtime.

The job's steps run as that same user, so they can modify the files the post step runs from.
Its output is therefore an **advisory record**. A genuine run reports accurately, but nothing
in the summary proves that it came from a genuine run.

What this does and doesn't affect:

- **Enforcement doesn't depend on the post step.** The proxy, resolver and firewall run as root
  or as dedicated users, set up in `pre`. In enforce, with sudo and docker removed, a non-root
  step can't change the monitored configuration in the first place.
- **What's at stake is the record:** the summary of what was blocked, the tamper verdict, and
  `fail-on-tampering` as a signal that something went wrong.
- **A small fix isn't on offer.** The whole launch path is owned by the runner user: the
  runner's install directory, its Node runtime, the action checkout, and the file-command files
  that carry the summary. Locking down one file would leave the rest, and would claim more than
  it delivers.

## Proposal: a root-owned supervisor with signed statements

1. **Install.** `pre` (root, before any job step runs) copies a small verifier into a
   root-owned path such as `/usr/local/libexec/safer-runner/`. It starts the verifier as a
   systemd unit, like the proxy and resolver units.
2. **Key.** At setup the supervisor generates an ephemeral Ed25519 key, stored root-only (0600),
   the same pattern as the CA key. `pre` prints the public key's fingerprint in its own log.
   Later steps can't rewrite an earlier step's log, so the fingerprint is authentic.
3. **Statements.** The supervisor computes the verdict itself and signs it. The verdict covers
   the integrity check plus digests of the flow, DNS and firewall logs, which are written by
   non-runner users. It runs periodically and on request. Each statement is bound to the run
   ID, attempt, job and time. The supervisor never signs content a caller supplies.
4. **Delivery.** The post step fetches the latest statement and prints it. If the statement is
   missing or invalid, the run counts as **unverified**, never as clean.
5. **Verification off the VM.** A follow-on job (`needs:`, on a fresh runner) reads the
   statement, checks it against the fingerprint from the `pre` log via the API, and fails if
   the statement is missing, invalid or reports tampering. This makes the verdict mean
   something, because the follow-on job runs outside the job it checks.
6. **Optional fail-closed in enforce.** When tampering is detected, the supervisor could stop
   the job out of band rather than wait for the post step. This is crude, so weigh it
   separately.

## Limits

- Anything with root on the VM defeats an on-VM supervisor: advisory mode (`disable-sudo:
  false`, `docker: keep`), or a privilege escalation. The supervisor only adds value in enforce
  with sudo and docker removed.
- Assurance only comes from verifying **off** the VM, which costs an extra job and API access to
  the run's logs.
- More moving parts: another unit, key handling, and a verifier to version alongside `dist/`.

## Recommendation

Keep the advisory labelling as the default posture. Build the supervisor and the follow-on
verifier only if there is demand for audit-grade evidence of a job's egress (for example to go
with the network-provenance artifact idea), and design both together.
