# Design: unified analyze mode + mode/control decoupling

**Status:** approved (Tim, 2026-11-08). Target: v2.x **minor** (one behaviour change to
`mode`; restores a sudo allowlist input). Build order: **sudo first**, then docker.

## Problem

`mode` currently conflates two independent axes:

1. **Enforce vs observe** — do we actually block, or just watch?
2. **Control defaults** — `mode` silently flips the unset defaults of `disable-sudo`,
   `docker`, `fail-on-tampering` (`src/config/inputs.ts`).

Because of (2), "switch to analyze" quietly also means "stop removing sudo / docker." That
coupling is what made `disable-sudo` hard to reason about and produced the pre→main
privilege-gap seam (analyze + explicit `disable-sudo` actually *tries* to restrict).

And analyze isn't uniform. Egress and `http-filter` get the full **observe → suggest a config →
enforce** paved road. **sudo does not**: v1 had a `sudo-config` allowlist and analyze suggested
one; v2 dropped it and made sudo binary (keep full / lock to read-only validation). The report
only says "enforce removes sudo". This is inconsistent — `http-filter` is *also* advisory yet
keeps its suggest loop.

## Principle

**`mode` is one axis, applied uniformly to every service.** The per-control **inputs define the
policy** (the *what*); **`mode` decides whether that policy is applied or merely
analyzed-and-suggested** (the *whether*).

- **analyze** = evaluate the declared policy against observed traffic, **never mutate the
  system**, log what *would* be blocked, and **suggest a config** that admits the observed
  legitimate usage.
- **enforce** = apply the policy.

Each service answers the same question: *"given these inputs, what did the job do that the
policy would block, and what config would cover the legitimate part?"*

## Per-service

| Service | Policy input | analyze output |
|---|---|---|
| Egress (DNS+proxy) | `allowed-domains`, `passthrough-domains` | would-block hosts; suggest `allowed-domains` **(template — unchanged)** |
| http-filter | `http-filter` | would-block paths/methods; suggest a filter **(unchanged)** |
| **sudo** | **restore `sudo-config` (structured YAML, see below)** | sudo calls the allowlist would block; **suggest a `sudo-config` from `sudo.log`** (advisory, loudly caveated — a sudo allowlist is not a hard boundary) |
| docker | `docker` (keep/remove-group/stop) | docker usage seen; note what `remove-group`/`stop` would have broken (built: see below) |
| fail-on-tampering | `fail-on-tampering` | stays a post-hoc report (doesn't fit "suggest a config") |

## Decisions (signed off)

1. **`sudo-config` shape:** a structured YAML input mirroring `http-filter`'s style (not v1's old
   format) — see the sudo slice below.
2. **Sudo suggester lives in Python**, a sibling of `proxy/suggest.py`, next to the sudo-log
   parsing, for symmetry with the http-filter suggester. TypeScript owns the YAML rendering (as
   it does for http-filter).
3. **Adopt the one behaviour change** (below).
4. **Build sudo first** (highest value, restores v1 parity), then docker.

## Mode semantics & the one behaviour change

New default model (removes the mode-coupling):

- The **intended policy defaults to locked-down regardless of mode** — unset `disable-sudo`
  behaves as "restrict", unset `docker` as "remove-group". `mode` then decides apply vs
  analyze+suggest.
- **Effective behaviour is unchanged for the common cases:** enforce still restricts by default;
  analyze still doesn't mutate the system (it never applies), so a job in analyze still runs with
  sudo/docker intact — exactly as today — but now *also* gets suggestions.

**The one deliberate behaviour change:** today, `analyze` + an **explicit** `disable-sudo: true`
actually restricts sudo (the pre→main seam). Under "analyze never mutates", that combination
**no longer restricts** — it observes + suggests instead. This dissolves the P1/P2 privilege-gap
findings rather than patching them, and makes analyze mean one clean thing ("analyze never
changes the system"). Release-noted.

(The explicit `disable-sudo: false` in enforce = ADVISORY path is unchanged.)

## Sudo slice (built first)

**Input `sudo-config`** — an allowlist of permitted sudo command lines. Proposed shape: a YAML
list of command patterns, parsed with the same `yaml` library and strict-schema approach as
`http-filter` (`src/config/inputs.ts`). Each entry is an absolute command path plus fixed
arguments, obeying the **both-flavour sudoers constraints** (valid for classic sudo *and*
sudo-rs): no wildcards among arguments except a lone trailing `*`, no `Defaults`, no aliases.
The parser fails the step (never last-wins) on a malformed entry.

```yaml
sudo-config: |
  - /usr/bin/apt-get install *
  - /usr/sbin/service nginx restart
```

**enforce:** the restricted sudoers is built from the validation commands (unchanged, always
present) **plus** the `sudo-config` allowlist — the middle ground between "full sudo" and
"read-only validation only". `disable-sudo: true` with no `sudo-config` = today's behaviour
(validation only). `disable-sudo: false` = keep full sudo (ADVISORY). The restricted sudoers is
still validated with the active `visudo` before install, fail-closed.

**analyze:** never restricts. The post step parses `sudo.log` (existing `report/logs/sudo-log.ts`),
classifies each command against the declared `sudo-config`, lists the commands that **would be
blocked**, and shows a **suggested `sudo-config`** built from the observed non-internal usage.
The suggester is Python (sibling of `proxy/suggest.py`), run via `src/suggest.ts`; TypeScript
renders the YAML. The action's own commands (`INTERNAL_SUDO_COMMANDS`) are filtered out, as today.

**Shared interface:** each service's `config.ts` grows one pure capability,
`evaluate(policy, observed) -> { wouldBlock, suggested }`, which the report (analyze) and the
suggesters call; enforce uses the existing `render`/apply. This is the provider-interface
instinct landing as a shared *analyze/suggest* interface, not a forced apply/teardown lifecycle.

### Sudo slice: as built

Where the build settled a detail the sections above left open:

- **Line syntax** (`parseSudoLine`, `src/services/sudo/config.ts`): an absolute, normalised path;
  arguments of letters, digits and `_ . / @ + -` only, so nothing ever needs sudoers escaping; a
  lone trailing `*` after at least one argument (`path *` alone is refused). At most 100 lines.
  Shared vectors: `proxy/test-vectors.json` "sudo" (jest and Python).
- **Sudoers**: the job's lines are a second alias, `SAFER_RUNNER_JOB`, run as `(root)` only. A
  command with no arguments is written `path ""` (bare, sudoers would allow any arguments). The
  file without `sudo-config` is unchanged.
- **Trailing `*`**: classic sudo needs the space before `*` (so at least one more argument);
  sudo-rs takes zero or more. The matcher (`ruleAllows`) takes the stricter: one or more.
- **Label**: any `sudo-config` makes enforce ADVISORY (we cannot prove a command is not
  root-equivalent). Setup warns on known root-equivalent commands (shells, interpreters,
  wrappers such as `timeout`/`nohup`/`setsid`, file writers such as `curl`/`tee`), on commands
  under a runner-writable path (`/home`, `/tmp`, the tool cache, `RUNNER_TEMP`, the workspace),
  and on a trailing `*`. The same warnings mark suggested lines (`# ⚠️` YAML comments).
- **Best effort**: the sudo log does not show `sudo -E` or argument boundaries (arguments are
  joined with spaces), so analyze can report a command as allowed that enforce refuses. Classic
  sudo's `ENV=` (variables on the command line) is detected: such a command would be blocked (no
  rule has SETENV) and is never suggested.
- **Suggestions** (`proxy/sudo_suggest.py`): exact observed lines only, never a `*`, capped at 50.
  A line that ran as another user, cannot be expressed, or has a secret-looking argument is left
  out and counted.
- **`evaluate`**: `evaluateSudo(rules, kept, ran)` returns the would-block list; the suggestion
  comes from the Python suggester, and the report puts the two together.
- **Checks**: `restrictSudo` only accepts a render that restricts, so analyze restricting does not
  compile; `SudoRule` is made only by the parser. Orchestration invariants L26 (analyze changes no
  sudoers) and L27 (the installed sudoers is exactly the validation commands plus `sudo-config`).
- **`disable-sudo` + `sudo-config` + mode:**

  | mode | disable-sudo | sudo-config | runner | summary |
  |---|---|---|---|---|
  | enforce | unset / true | none | validation-only sudoers | sudo removed |
  | enforce | unset / true | lines | validation + the lines (root) | ADVISORY, sudo allowlist (N) |
  | enforce | false | none | sudo kept | ADVISORY, sudo retained |
  | either | false | lines | step fails | — |
  | analyze | unset / true | none / lines | unchanged | would-block list + suggested sudo-config |
  | analyze | false | none | unchanged | sudo kept: enforce would be ADVISORY |

## Docker slice: as built

Approved (Tim, 2026-11-08) with six decisions: adopt the docker behaviour change; keep the
dockerd CA restart in analyze; show a `docker: keep` suggestion with its caveat; never suggest
`stop` over the policy; record docker events with a recorder unit; leave `fail-on-tampering`
mode-aware.

- **Default and mode**: unset `docker` is `remove-group` in both modes (`resolveDocker`).
  `planDocker(mode, policy)` returns the access change, an `ApplyingDocker`, only in enforce; the
  functions that change docker access take one, so analyze changing it does not compile.
  Analyze is treated as `keep`.
- **The docker behaviour change**: analyze with an explicit `docker: remove-group` or `stop` no
  longer applies it (setup warns). In that case dockerd now restarts for the proxy CA and the
  containers get the container rules, as with analyze unset, because docker stays usable.
- **Not access**: the dockerd CA restart and the `daemon.json` `live-restore` merge are the
  proxy's precondition (F1) and run in analyze too. L28 (analyze changes no docker access)
  covers the group, the socket and stopping or disabling the daemon.
- **Signal**: analyze runs `docker events` in a transient unit from setup on
  (`eventRecorderUnit`), read only, no network, never restarted, and only if `docker.service`
  already runs: `docker events` against a socket-activated daemon would start it (L29). dockerd
  holds only its latest events, so querying it at the end could miss an early use. Without a
  recording, the post step asks dockerd for what it still holds (if it runs), and calls the
  result partial.
- **What counts as use** (`classifyDockerEvents`): every event except dockerd's own (exits,
  `oom`, health status, its reload) and a container's healthcheck exec (the exec command equals
  its `Config.Healthcheck`). A step's `docker exec` into a service container counts.
- **`evaluate`**: `evaluateDocker(policy, observed)` returns what the policy would block (any
  use, under `remove-group` or `stop`), the service containers `stop` would stop, and a
  suggestion `{ input: 'docker', value, advisory, change }` for the report's later "Suggested
  enforce configuration": any use needs `keep` (ADVISORY); `stop` with service containers, or
  `keep` with no use, gets `remove-group`; otherwise the policy stays.
- **Shown**: kinds, counts and image names (each part through the label check), never an exec
  command, container name, label or the environment.

## Backwards-compat

- Restores `sudo-config` (removed in v2; v2 is young, so blast radius is small).
- `mode`-semantics change is additive for common cases + one documented change for
  `analyze` + explicit `disable-sudo`.
- Ship as a v2.x **minor** with release notes; no floating `@v2` (pin exact version / SHA).

## Gate

Sudo is security-critical (the sudo-restriction / L21 path): **full gate** — real-runner matrix
+ adversarial review — per the established flow.
