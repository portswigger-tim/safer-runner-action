"""safer-runner v2: the suggested ``sudo-config`` for the job summary (analyze; advisory, never applied).

Built from the workflow's own sudo commands (the post step reads the sudo log, drops the action's
own commands and sends the rest here as JSON; src/report/suggest.ts). A sibling of suggest.py, the
http-filter suggester, and it reuses its encoded-data heuristic.

Exact command lines only: a suggestion never contains a ``*``. In classic sudo a trailing ``*``
matches across arguments, options included, so it is never put in front of a user as a safe
default (a user may still write one by hand). A line is left out, and counted, when it cannot be
written as a sudo-config line, when an argument looks like a secret, or when it ran as another
user (sudo-config rules run as root only).

Run as ``python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); import sudo_suggest;
sudo_suggest.main()' <this dir>``: reads ``{"commands": [{"command", "args", "targetUser"}]}`` on
stdin, writes ``{"rules": [line], "omitted": {...}}`` on stdout.
"""

import json
import re
import sys

from suggest import looks_encoded

MAX_RULES = 50

# what a sudo-config line may contain (src/services/sudo/config.ts parseSudoLine): nothing sudoers
# would need escaped, and here no `*` at all
_PATH = re.compile(r"(/[A-Za-z0-9_.@+-]+)+", re.ASCII)
_WORD = re.compile(r"[A-Za-z0-9_./@+-]+", re.ASCII)

# credentials with a known shape
_TOKEN_PREFIX = re.compile(
    r"(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|xox[abprs]-|npm_|AKIA|ASIA|sk-)", re.ASCII
)
_LONG_RUN = re.compile(r"[A-Za-z0-9]{32,}", re.ASCII)
_PART = re.compile(r"[/.@+_=:-]", re.ASCII)
SECRET_PART_LEN = 16
# a flag whose value is a credential: the next argument (or the value after `=`) is never printed
_SECRET_FLAGS = {"--password", "--passwd", "--pass", "--token", "--secret", "--api-key", "--apikey", "--auth"}
# `NAME=value` with a name like these: the value is a credential
_SECRET_NAME = re.compile(r"pass|pwd|secret|token|key|auth|cred|cookie|session", re.ASCII | re.IGNORECASE)
# words an HTTP credential follows (`-H Authorization: Bearer x`, joined by spaces in the sudo log)
_AUTH_WORDS = {"authorization", "bearer", "basic", "token", "cookie", "x-api-key"}
# `scheme://user:password@`
_USERINFO = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/@\s]*:[^/@\s]*@", re.ASCII)


def representable(path, args):
    """Can this command be written as an exact sudo-config line?"""
    if not _PATH.fullmatch(path) or any(seg in (".", "..") for seg in path.split("/")[1:]):
        return False
    if path.rsplit("/", 1)[-1] == "sudoedit":
        return False
    return all(_WORD.fullmatch(a) for a in args)


def looks_secret(arg):
    """Could this argument be a credential? Best effort; a false positive only leaves a line out."""
    if _TOKEN_PREFIX.match(arg) or _LONG_RUN.search(arg):
        return True
    return any(len(p) >= SECRET_PART_LEN and looks_encoded(p) for p in _PART.split(arg))


def _short_p_value(arg):
    """`-phunter2` (mysql), not `-p22` (a port) or `-p/x` (a path)."""
    return len(arg) > 2 and arg[:2] in ("-p", "-P") and arg[2] not in "-/." and not arg[2:].isdigit()


def secret_mask(args):
    """For each argument, could it carry a credential? (src/report/redact.ts secretMask: the report
    prints a masked argument as a placeholder; a suggestion leaves the whole line out.)"""
    mask = []
    for i, a in enumerate(args):
        prev = args[i - 1] if i else ""
        name, eq, value = a.partition("=")
        mask.append(
            looks_secret(a)
            or prev.lower() in _SECRET_FLAGS
            # `mysql -p hunter2`; not `mkdir -p /x` (a path) or `ssh -p 22` (a port)
            or (prev in ("-p", "-P") and not a.startswith(("/", ".", "-")) and not a.isdigit())
            or _short_p_value(a)
            # `curl -u user:password`
            or (prev in ("-u", "--user") and ":" in a)
            or prev.lower().rstrip(":") in _AUTH_WORDS
            or (bool(eq) and (name.lower() in _SECRET_FLAGS or bool(_SECRET_NAME.search(name)) or looks_secret(value)))
            or bool(_USERINFO.search(a))
        )
    return mask


def has_secret(args):
    """An argument that looks like a credential, or the value of a password-like flag."""
    return any(secret_mask(args))


def path_secret(path):
    """A command path with a segment that looks like encoded data (`/tmp/<token>/run`)."""
    return any(
        looks_secret(seg) or any(looks_encoded(piece) for piece in seg.split("."))
        for seg in path.split("/")
        if seg
    )


def suggest(commands):
    """Exact sudo-config lines for these commands, and how many distinct lines were left out, and why."""
    lines = set()
    omitted = {"secret": set(), "unrepresentable": set(), "other_user": set()}
    for c in commands:
        path = c.get("command")
        args = (c.get("args") or "").split()
        if not isinstance(path, str):
            continue
        line = " ".join([path, *args])
        if (c.get("targetUser") or "root") != "root":
            omitted["other_user"].add(line)
        elif c.get("env") or not representable(path, args):
            # environment variables need SETENV, which a sudo-config rule never has
            omitted["unrepresentable"].add(line)
        elif path_secret(path) or has_secret(args):
            omitted["secret"].add(line)
        else:
            lines.add(line)
    rules = sorted(lines)
    return {
        "rules": rules[:MAX_RULES],
        "omitted": {
            "secret": len(omitted["secret"]),
            "unrepresentable": len(omitted["unrepresentable"]),
            "other_user": len(omitted["other_user"]),
            "over_cap": max(0, len(rules) - MAX_RULES),
        },
    }


def main():
    data = json.load(sys.stdin)
    commands = data.get("commands") if isinstance(data, dict) else None
    if not isinstance(commands, list):
        raise SystemExit('sudo_suggest: expected {"commands": [...]} on stdin')
    json.dump(suggest(c for c in commands if isinstance(c, dict)), sys.stdout)
