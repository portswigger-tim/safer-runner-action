# Repository hardening: settings only the owner can apply

The code side of the release path is in the repo (pinned workflows,
[release.yml](../../.github/workflows/release.yml) with a reproducibility gate and build
provenance, [CODEOWNERS](../../.github/CODEOWNERS), [Dependabot](../../.github/dependabot.yml),
[SECURITY.md](../../SECURITY.md)). None of it stops someone with push access from moving a
tag or pushing straight to a release branch. These settings do. They need an admin of
`portswigger-tim/safer-runner-action`; no workflow or agent applies them.

State when this was written (2026-11-05, read with `gh api`): no branch protection, no
rulesets, private vulnerability reporting **off**, immutable releases **off**, SHA pinning
**not** required, default workflow token **read-only** (good, keep it).

```bash
R=portswigger-tim/safer-runner-action
```

Each step is independent. Apply in this order; the ones marked **decide first** change how
day-to-day work is done.

## 1. Private vulnerability reporting (needed by SECURITY.md)

SECURITY.md tells reporters to use **Security → Report a vulnerability**. That button only
exists when this is on.

```bash
gh api -X PUT repos/$R/private-vulnerability-reporting
gh api repos/$R/private-vulnerability-reporting   # {"enabled":true}
```

UI: Settings → Security → Advanced Security (or "Code security") → **Private vulnerability
reporting** → Enable.

## 2. Immutable releases

Once a release is **published**, its tag can't be moved or deleted and its assets can't be
changed. Drafts stay editable; release.yml only creates drafts, so the notes can be written
before publishing. Doesn't affect `v1`/`v2` floating tags (they have no release).

```bash
gh api -X PUT repos/$R/immutable-releases
gh api repos/$R/immutable-releases   # {"enabled":true,...}
```

UI: Settings → General → Releases → **Enable release immutability**.

## 3. Tag rulesets

Two rulesets, because they need different bypass lists:

- **Release tags (`v*.*.*`, including `-beta.N`) can never be moved or deleted**, by anyone.
- **Only an admin can create or move any `v*` tag**, which keeps moving `v1` / `v2` possible
  for you and impossible for a workflow token, a bot, or another collaborator.

Rules from both apply, so an admin can create `v2.0.0` and move `v2`, but can't move
`v2.0.0` afterwards (except by disabling the ruleset, which is logged).

```bash
gh api -X POST repos/$R/rulesets --input - <<'EOF'
{
  "name": "release tags are immutable",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*.*.*"], "exclude": [] } },
  "rules": [ { "type": "update" }, { "type": "deletion" } ],
  "bypass_actors": []
}
EOF

gh api -X POST repos/$R/rulesets --input - <<'EOF'
{
  "name": "only admins create or move v* tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "creation" }, { "type": "update" }, { "type": "deletion" } ],
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" } ]
}
EOF
```

(`actor_id: 5` is the built-in **Admin** repository role.)

UI: Settings → Rules → Rulesets → New ruleset → **New tag ruleset**. Target tags by pattern
`v*.*.*` (first) / `v*` (second), tick the rules above, and for the second add **Repository
admin** to the bypass list.

Check: `gh api repos/$R/rulesets`. Then try moving an existing beta tag; it must be refused:
`git push --force origin <sha>:refs/tags/v2.0.0-beta.1` → `GH013: Repository rule violations`.

The existing `v1.x.y` and `v2.0.0-beta.N` tags become immutable as soon as the first ruleset
is active.

## 4. Branch rulesets for `main` and `v2` (**decide first**)

Requires a pull request with green CI for every change to a release branch, and blocks
force-push and deletion. `bypass_mode: "pull_request"` lets an admin merge a PR that doesn't
meet the rules (you can't approve your own PR) but not push directly.

**Impact:** agent sessions currently push straight to `origin/v2` and `origin/main`. With
this ruleset they would have to push a branch and open a PR, and you (or a merge rule you
grant) merge it. If you're not ready for that on `v2`, apply it to `main` only for now
(remove `refs/heads/v2` from `include`).

```bash
gh api -X POST repos/$R/rulesets --input - <<'EOF'
{
  "name": "release branches: PR + CI, no force-push",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main", "refs/heads/v2"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request", "parameters": {
        "required_approving_review_count": 0,
        "require_code_owner_review": false,
        "dismiss_stale_reviews_on_push": true,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false } },
    { "type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [ { "context": "build-and-verify", "integration_id": 15368 } ] } }
  ],
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" } ]
}
EOF
```

- `build-and-verify` is the job in [ci.yml](../../.github/workflows/ci.yml) (tests + `dist/`
  rebuild check). `integration_id: 15368` is the GitHub Actions app, so only a check reported
  by Actions satisfies it.
- CI must exist on the branch for the check to report. `main` (v1) has no workflows today
  (removed for Marketplace publishing), so on `main` a required check would block every PR.
  Either add `ci.yml` to `main` first, or create the `main` ruleset without the
  `required_status_checks` rule.
- With more than one maintainer, set `required_approving_review_count: 1` and
  `require_code_owner_review: true` so CODEOWNERS is enforced. With one maintainer those
  settings only add an admin-bypass click to every merge.

UI: Settings → Rules → Rulesets → New branch ruleset; same rules. Add **Repository admin** to
bypass with **For pull requests only**.

## 5. Actions settings

Require every `uses:` to be pinned to a full SHA (all workflows in the repo already are) and
allow only GitHub-authored actions (the only ones used):

```bash
gh api -X PUT repos/$R/actions/permissions \
  -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true
gh api -X PUT repos/$R/actions/permissions/selected-actions \
  -F github_owned_allowed=true -F verified_allowed=false
gh api repos/$R/actions/permissions
```

UI: Settings → Actions → General → **Allow select actions** ("Allow actions created by
GitHub"), and **Require actions to be pinned to a full-length commit SHA**.

Also, in the same page:

- **Workflow permissions:** keep **Read repository contents** (current).
- **Allow GitHub Actions to create and approve pull requests:** needed only by
  `update-github-domains.yml` to open its PR. Turn it on if you use that workflow; with the
  ruleset above (0 required approvals) there is no approval to abuse.
- **Approval for running fork pull request workflows:** **Require approval for all external
  contributors**.

## 6. Secret scanning and push protection

Free on public repos.

```bash
gh api -X PATCH repos/$R --input - <<'EOF'
{ "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" } } }
EOF
```

UI: Settings → Security → Advanced Security → Secret Protection / Push protection.

## 7. Account security (optional but cheap)

The rulesets above all have an admin bypass, so the owner account is the root of trust.

- **2FA with a passkey or security key** on the `portswigger-tim` account (github.com →
  Settings → Password and authentication). This is per account; a user-owned repo can't
  enforce it for collaborators.
- Review **Collaborators**, **Deploy keys** and **fine-grained / classic tokens** with write
  access to this repo; remove anything not in use:
  `gh api repos/$R/collaborators -q '.[].login'`, `gh api repos/$R/keys`.
- **Signed commits / tags (if wanted):** set up SSH signing locally
  (`git config --global gpg.format ssh`, `user.signingkey ~/.ssh/<key>.pub`,
  `commit.gpgsign true`, `tag.gpgsign true`), upload the key with
  `gh ssh-key add ~/.ssh/<key>.pub --type signing`, then add `{ "type": "required_signatures" }`
  to the branch ruleset (step 4). Every pusher, including agent sessions, then needs a
  signing key; squash merges made in the GitHub UI are signed by GitHub.

## After applying

- `gh api repos/$R/rulesets` lists three rulesets; `immutable-releases` and
  `private-vulnerability-reporting` report enabled.
- The next `v*` tag pushed on a commit that contains `release.yml` runs the Release workflow:
  verify → attest → draft release. Check the run is green and that
  `gh attestation verify dist/main/index.js --repo $R --source-digest <sha>` passes before
  publishing the draft or moving `v2`.
- The Release workflow only exists on `v2`. Tags on `main` (v1.x.y) get no attestation until
  `release.yml` is also on `main`.
- Dependabot reads its config from the default branch (`main`) only, so it starts once
  `.github/dependabot.yml` is on `main`.
