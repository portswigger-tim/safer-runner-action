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
_PART = re.compile(r"[/.@+_-]", re.ASCII)
SECRET_PART_LEN = 16
# a flag whose value is a credential: the next argument is never printed
_SECRET_FLAGS = {"--password", "--passwd", "--pass", "--token", "--secret", "--api-key", "--apikey", "--auth"}


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


def has_secret(args):
    """An argument that looks like a credential, or the value of a password-like flag."""
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else None
        if looks_secret(a):
            return True
        if nxt is not None and a.lower() in _SECRET_FLAGS:
            return True
        # `mysql -p hunter2` / `-phunter2`; not `mkdir -p /x` (a path) or `ssh -p 22` (a port)
        if a in ("-p", "-P") and nxt is not None and not nxt.startswith(("/", ".", "-")) and not nxt.isdigit():
            return True
        if len(a) > 2 and a[:2] in ("-p", "-P") and a[2] not in "-/." and not a[2:].isdigit():
            return True
    return False


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
        elif has_secret(args):
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
