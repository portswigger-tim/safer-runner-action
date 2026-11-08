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
| docker | `docker` (keep/remove-group/stop) | docker usage seen; note what `remove-group`/`stop` would have broken |
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

## Backwards-compat

- Restores `sudo-config` (removed in v2; v2 is young, so blast radius is small).
- `mode`-semantics change is additive for common cases + one documented change for
  `analyze` + explicit `disable-sudo`.
- Ship as a v2.x **minor** with release notes; no floating `@v2` (pin exact version / SHA).

## Gate

Sudo is security-critical (the sudo-restriction / L21 path): **full gate** — real-runner matrix
+ adversarial review — per the established flow.
