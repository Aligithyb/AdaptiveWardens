"""Deterministic command responses that should NEVER hit the LLM.

The SSH frontend has a much larger STATIC_RESPONSES dict; this is a smaller
backstop on the AI-engine side so that if a deterministic command somehow
reaches /generate-response (e.g. SSH server missed a variant), we still
short-circuit instead of burning DeepSeek tokens.

A function may return a string (the response) or None (no opinion, fall through).
Functions receive (command, context). Match is exact lowercase command unless
the entry is a (matcher_fn, responder_fn) tuple.
"""

import re

HOSTNAME = "api-prod-01"


def _whoami(_cmd, ctx):
    return ctx.get("username", "root")


def _id(_cmd, ctx):
    user = ctx.get("username", "root")
    if user == "root":
        return "uid=0(root) gid=0(root) groups=0(root),4(adm),27(sudo)"
    return f"uid=1000({user}) gid=1000({user}) groups=1000({user})"


def _hostname(_cmd, _ctx):
    return HOSTNAME


def _pwd(_cmd, ctx):
    return ctx.get("current_directory", "/root")


def _uname(cmd, _ctx):
    c = cmd.strip()
    if c == "uname":
        return "Linux"
    if c in ("uname -a", "uname --all"):
        return (f"Linux {HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP "
                "Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux")
    if c in ("uname -s",):
        return "Linux"
    if c in ("uname -r",):
        return "5.15.0-91-generic"
    if c in ("uname -m",):
        return "x86_64"
    if c in ("uname -n",):
        return HOSTNAME
    if c in ("uname -o",):
        return "GNU/Linux"
    return None


def _echo(cmd, _ctx):
    m = re.match(r'^echo\s+(.*)$', cmd, re.DOTALL)
    if not m:
        return None
    rest = m.group(1).strip()
    if any(s in rest for s in ("$", "`", "$(", "${", "*", "?", ">", "<", "|", "&", ";")):
        return None
    if rest.startswith('"') and rest.endswith('"'):
        return rest[1:-1]
    if rest.startswith("'") and rest.endswith("'"):
        return rest[1:-1]
    return rest


def _true(_cmd, _ctx):
    return ""


def _false(_cmd, _ctx):
    return ""


_KNOWN_BINARIES = {
    "ls": "/usr/bin/ls", "cat": "/usr/bin/cat", "grep": "/usr/bin/grep",
    "awk": "/usr/bin/awk", "sed": "/usr/bin/sed", "ps": "/usr/bin/ps",
    "curl": "/usr/bin/curl", "wget": "/usr/bin/wget", "nc": "/usr/bin/nc",
    "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp", "bash": "/usr/bin/bash",
    "sh": "/usr/bin/sh", "python3": "/usr/bin/python3", "node": "/usr/bin/node",
    "git": "/usr/bin/git", "docker": "/usr/bin/docker", "kubectl": "/usr/bin/kubectl",
    "psql": "/usr/bin/psql", "redis-cli": "/usr/bin/redis-cli", "vim": "/usr/bin/vim",
    "nano": "/usr/bin/nano", "tar": "/usr/bin/tar", "gzip": "/usr/bin/gzip",
    "find": "/usr/bin/find", "xargs": "/usr/bin/xargs",
}


def _which(cmd, _ctx):
    m = re.match(r'^(which|command\s+-v|type)\s+(\S+)\s*$', cmd)
    if not m:
        return None
    target = m.group(2)
    if target in _KNOWN_BINARIES:
        if m.group(1) == "type":
            return f"{target} is {_KNOWN_BINARIES[target]}"
        return _KNOWN_BINARIES[target]
    if m.group(1) == "type":
        return f"-bash: type: {target}: not found"
    return ""  # exit 1, no output


def _printenv(cmd, ctx):
    parts = cmd.split()
    if len(parts) == 1:
        return None  # full env — let LLM/static handle
    if len(parts) != 2:
        return None
    var = parts[1]
    env = ctx.get("environment", {}) or {}
    defaults = {
        "HOME": "/root", "USER": ctx.get("username", "root"),
        "SHELL": "/bin/bash", "TERM": "xterm-256color",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8", "PWD": ctx.get("current_directory", "/root"),
        "HOSTNAME": HOSTNAME, "LOGNAME": ctx.get("username", "root"),
    }
    if var in env:
        return env[var]
    if var in defaults:
        return defaults[var]
    return ""


_EXACT = {
    "whoami": _whoami,
    "id": _id,
    "hostname": _hostname,
    "hostname -s": _hostname,
    "hostname -f": lambda c, ctx: f"{HOSTNAME}.nexopay.internal",
    "pwd": _pwd,
    "true": _true,
    ":": _true,
    "false": _false,
    "uptime -p": lambda c, ctx: "up 1 week, 4 days, 6 hours",
    "id -u": lambda c, ctx: "0" if ctx.get("username", "root") == "root" else "1000",
    "id -g": lambda c, ctx: "0" if ctx.get("username", "root") == "root" else "1000",
    "id -un": lambda c, ctx: ctx.get("username", "root"),
}

_PREFIX = [
    (re.compile(r'^uname(\s|$)'), _uname),
    (re.compile(r'^echo(\s|$)'), _echo),
    (re.compile(r'^(which|command\s+-v|type)\s'), _which),
    (re.compile(r'^printenv(\s|$)'), _printenv),
]


def lookup(command: str, context: dict):
    """Return (response_str, scope) or None if no deterministic answer.

    scope is one of 'global' / 'per_user' / 'per_cwd' so the caller can pick
    an appropriate cache key (though deterministic results don't need caching).
    """
    cmd = command.strip()
    lc = cmd.lower()

    if lc in _EXACT:
        out = _EXACT[lc](cmd, context)
        if out is not None:
            return out, _scope_for(lc)

    for pattern, handler in _PREFIX:
        if pattern.match(lc):
            out = handler(cmd, context)
            if out is not None:
                return out, _scope_for(lc)

    return None


def _scope_for(lc: str) -> str:
    if lc.startswith(("whoami", "id", "hostname", "uname", "true", "false", ":", "echo ")):
        return "global"
    if lc.startswith(("pwd", "printenv")):
        return "per_user"
    return "per_cwd"
