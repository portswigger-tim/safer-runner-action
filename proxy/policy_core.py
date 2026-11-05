"""safer-runner v2 egress policy: pure decision logic (no mitmproxy imports).

Kept separate from the mitmproxy addon (policy.py) so it can be unit-tested with a plain
Python interpreter, and so the hostname-matching rules can be checked against the same
test vectors as the TypeScript side (proxy/test-vectors.json).

Pattern semantics (mirrors src/policy.ts):
  * ``example.com``      -> exactly example.com (no subdomains)
  * ``*.example.com``    -> any subdomain of example.com (not the apex)
  * ``a-*.example.com``  -> ``*`` matches within ONE label; the rest must match exactly

Decisions are made on names only, never on the destination IP the client chose.

Container sources (P2): traffic containers send off their bridge arrives on a second proxy
listener. With ``container_tls: sni-only`` (the default) an allowlisted name from a container
is passed through by SNI (repointed, IP-pinned, never decrypted - no CA needed inside the
container), except for multi-tenant front doors (FRONT_DOORS), which stay intercepted in
enforce so the Host check still stops fronting to another tenant behind the same front end.
"""

import ipaddress
import json
import re

# Verdicts written to the flow log.
INTERCEPT = "INTERCEPT"  # TLS terminated with our CA, Host enforced per request
PASSTHROUGH = "PASSTHROUGH"  # TLS not decrypted, SNI enforced, upstream repointed
ALLOW = "ALLOW"  # HTTP request allowed
BLOCK = "BLOCK"  # enforce mode: refused
WOULD_BLOCK = "WOULD_BLOCK"  # analyze mode: would have been refused, allowed and logged

# Flow-log ``source`` of a connection: which proxy listener it arrived on.
SOURCE_HOST = "host"
SOURCE_CONTAINER = "container"

CONTAINER_TLS_MODES = ("sni-only", "intercept")

# Multi-tenant front doors: one TLS front end serves every tenant and routes by Host, so an
# SNI-only check of an allowlisted tenant would let a client reach ANY tenant (domain fronting).
# Under container sni-only these stay intercepted for containers in enforce (fail closed when
# the container doesn't trust the CA). Mirrored in src/policy.ts; both are checked against
# proxy/test-vectors.json "front_doors".
FRONT_DOORS = (
    "*.blob.core.windows.net",
    "*.dfs.core.windows.net",
    "*.file.core.windows.net",
    "*.queue.core.windows.net",
    "*.table.core.windows.net",
    "*.web.core.windows.net",
)

_LABEL = re.compile(r"^[a-z0-9_*]([a-z0-9_*-]*[a-z0-9_*])?$")


class PolicyError(ValueError):
    pass


def norm_host(host):
    """Lower-case, strip a trailing dot and any :port. Returns '' for empty input."""
    if not host:
        return ""
    host = str(host).strip().lower()
    if host.startswith("["):  # [v6]:port
        end = host.find("]")
        return host[1:end] if end > 0 else host
    if host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host.rstrip(".")


def is_ip_literal(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_pattern(pattern):
    """Return the normalised pattern or raise PolicyError."""
    p = norm_host(pattern)
    if not p or "." not in p:
        raise PolicyError(f"not a domain pattern: {pattern!r}")
    if is_ip_literal(p):
        raise PolicyError(f"IP literals are not allowed in patterns: {pattern!r}")
    labels = p.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise PolicyError(f"invalid domain pattern: {pattern!r}")
    if any("*" in label for label in labels[-2:]):
        raise PolicyError(f"wildcard too broad (in the registrable part): {pattern!r}")
    if p.startswith("*.") and "*" in p[2:]:
        raise PolicyError(f"only one wildcard form per pattern: {pattern!r}")
    return p


def compile_pattern(pattern):
    p = validate_pattern(pattern)
    if p.startswith("*."):
        body = r"(?:[a-z0-9_-]+\.)+" + re.escape(p[2:])
    elif "*" in p:
        body = re.escape(p).replace(r"\*", r"[a-z0-9_-]*")
    else:
        body = re.escape(p)
    return re.compile("^" + body + "$")


def matches(host, compiled):
    host = norm_host(host)
    return bool(host) and any(c.match(host) for c in compiled)


# Upstream addresses the proxy never connects to, whatever name led there (review H1): an
# allowlisted name whose DNS an attacker controls must not become a route to the metadata
# service, loopback or the private network. Explicit list (not ipaddress.is_private, whose
# meaning changed between Python versions).
FORBIDDEN_UPSTREAM_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network"
        "10.0.0.0/8",  # RFC 1918
        "100.64.0.0/10",  # CGNAT (RFC 6598) - dnsmasq's stop-dns-rebind does not cover it
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, incl. IMDS 169.254.169.254
        "172.16.0.0/12",  # RFC 1918
        "192.168.0.0/16",  # RFC 1918
        "168.63.129.16/32",  # Azure wireserver (reached directly by the platform, never by name)
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved + broadcast
        "::/128",
        "::1/128",
        "fe80::/10",  # link-local
        "fc00::/7",  # ULA
        "ff00::/8",  # multicast
    )
)

UPSTREAM_FORBIDDEN = "upstream-ip-forbidden"
UPSTREAM_UNRESOLVED = "upstream-unresolved"


def forbidden_upstream(ip):
    """True if the proxy must not connect to ``ip`` (unparseable counts as forbidden)."""
    try:
        a = ipaddress.ip_address(str(ip).split("%", 1)[0])  # drop an IPv6 zone id
    except ValueError:
        return True
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return any(a.version == n.version and a in n for n in FORBIDDEN_UPSTREAM_NETS)


def pick_upstream(addrs):
    """Choose the address to pin from a name's resolved addresses (resolver order).

    Returns ``(ip, reason)``: reason None means connect to ip; otherwise ip is the offending
    address (None if nothing resolved). One forbidden address rejects the whole answer, so an
    attacker can't hide an internal address behind a public one. IPv4 is preferred because
    there is no IPv6 egress path for the proxy (review L2).
    """
    addrs = [str(a) for a in addrs if a]
    if not addrs:
        return None, UPSTREAM_UNRESOLVED
    for a in addrs:
        if forbidden_upstream(a):
            return a, UPSTREAM_FORBIDDEN
    v4 = [a for a in addrs if ":" not in a]
    return (v4 or addrs)[0], None


class Decision:
    __slots__ = ("action", "reason")

    def __init__(self, action, reason):
        self.action = action
        self.reason = reason

    def __repr__(self):
        return f"Decision({self.action!r}, {self.reason!r})"


class Policy:
    """Hostname policy. ``mode`` is 'enforce' or 'analyze'."""

    def __init__(self, mode, allow, passthrough, deny, container_tls="intercept"):
        if mode not in ("enforce", "analyze"):
            raise PolicyError(f"invalid mode: {mode!r}")
        if container_tls not in CONTAINER_TLS_MODES:
            raise PolicyError(f"invalid container_tls: {container_tls!r}")
        self.mode = mode
        self.container_tls = container_tls
        self._front_doors = [compile_pattern(p) for p in FRONT_DOORS]
        self.allow_patterns = [validate_pattern(p) for p in allow]
        self.passthrough_patterns = [validate_pattern(p) for p in passthrough]
        self.deny_patterns = [validate_pattern(p) for p in deny]
        self._allow = [compile_pattern(p) for p in self.allow_patterns]
        self._pass = [compile_pattern(p) for p in self.passthrough_patterns]
        self._deny = [compile_pattern(p) for p in self.deny_patterns]

    @classmethod
    def from_config(cls, cfg):
        return cls(
            cfg["mode"],
            cfg.get("allow", []),
            cfg.get("passthrough", []),
            cfg.get("deny", []),
            # absent (older config): containers are treated exactly like the host
            cfg.get("container_tls", "intercept"),
        )

    @classmethod
    def load(cls, path):
        with open(path) as f:
            cfg = json.load(f)
        return cls.from_config(cfg), cfg

    @property
    def enforce(self):
        return self.mode == "enforce"

    def is_allowed_name(self, host):
        """Allowed for HTTP Host purposes: allowlisted or passthrough, and not denied."""
        if matches(host, self._deny):
            return False
        return matches(host, self._allow) or matches(host, self._pass)

    def is_front_door(self, host):
        return matches(host, self._front_doors)

    def decide_tls(self, sni, source=SOURCE_HOST):
        """Decision at the TLS ClientHello: block | passthrough | intercept.

        For a container source under ``container_tls: sni-only``, an allowlisted name that
        would be intercepted is passed through instead (reason ``container-sni-only``), unless
        it is a multi-tenant front door in enforce (reason ``container-front-door``: still
        intercepted, so the Host check holds). Blocks are never relaxed.
        """
        d = self._decide_tls(sni)
        if source != SOURCE_CONTAINER or self.container_tls != "sni-only" or d.action != "intercept":
            return d
        if self.enforce and self.is_front_door(sni):
            return Decision("intercept", "container-front-door")
        return Decision("passthrough", "container-sni-only")

    def _decide_tls(self, sni):
        name = norm_host(sni)
        if not name:
            return Decision("block", "no-sni")
        if is_ip_literal(name):
            return Decision("block", "ip-literal-sni")
        if matches(name, self._deny):
            return Decision("block", "sni-denied")
        if matches(name, self._pass):
            return Decision("passthrough", "passthrough")
        if matches(name, self._allow):
            return Decision("intercept", "allowed")
        return Decision("block", "sni-not-allowed")

    def decide_http(self, host_header, others=(), method="GET", sni=None):
        """Decision for one HTTP request (plain, or decrypted inside intercepted TLS).

        ``others`` are any further statements of the target the request carries (HTTP/1
        absolute-form authority, an HTTP/2 :authority alongside a Host header); all of
        them must agree with ``host_header``.
        """
        host = norm_host(host_header)
        if (method or "").upper() == "CONNECT":
            return Decision("block", "connect-method")
        if not host:
            return Decision("block", "no-host")
        if is_ip_literal(host):
            return Decision("block", "ip-literal-host")
        if isinstance(others, str):
            others = (others,)
        if any(norm_host(o) and norm_host(o) != host for o in others):
            return Decision("block", "authority-host-mismatch")
        if sni is not None and host != norm_host(sni):
            return Decision("block", "host-sni-mismatch")  # domain fronting
        if matches(host, self._deny):
            return Decision("block", "host-denied")
        if not self.is_allowed_name(host):
            return Decision("block", "host-not-allowed")
        return Decision("allow", "allowed")


def selftest(policy):
    """Invariants that must hold for any loaded policy. Raises AssertionError on failure."""
    probe = "selftest.safer-runner.invalid"
    assert policy.decide_tls(probe).action == "block", "unknown SNI not blocked"
    assert policy.decide_tls("").action == "block", "missing SNI not blocked"
    assert policy.decide_tls("1.2.3.4").action == "block", "IP-literal SNI not blocked"
    assert policy.decide_http(probe).action == "block", "unknown Host not blocked"
    assert policy.decide_http("1.2.3.4").action == "block", "IP-literal Host not blocked"
    assert policy.decide_http("", method="GET").action == "block", "missing Host not blocked"
    for p in policy.allow_patterns:
        concrete = p.replace("*", "x")
        if matches(concrete, policy._deny):
            continue
        assert policy.decide_http(concrete, sni=probe).action == "block", "Host!=SNI not blocked"
    for ip in ("169.254.169.254", "127.0.0.1", "10.0.0.1", "100.64.0.1", "::1", "::ffff:169.254.169.254"):
        assert pick_upstream([ip])[1] == UPSTREAM_FORBIDDEN, f"upstream {ip} not refused"
    assert pick_upstream(["140.82.112.3"]) == ("140.82.112.3", None), "public upstream refused"
    # container posture never relaxes a block
    for name in (probe, "", "1.2.3.4"):
        assert policy.decide_tls(name, SOURCE_CONTAINER).action == "block", "container SNI block relaxed"
    if policy.enforce and policy.container_tls == "sni-only":
        fd = "selftest.blob.core.windows.net"
        assert policy.is_front_door(fd), "front door not recognised"
    return True
