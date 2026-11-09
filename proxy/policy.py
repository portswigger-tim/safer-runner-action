"""safer-runner v2 egress policy addon for mitmproxy (transparent mode).

Loaded with ``mitmdump -s policy.py``. The decision logic lives in policy_core.py; this file
wires it into mitmproxy. PINNED to mitmproxy 12.3.1: it uses layer classes that are not a
stable public API, so it refuses to start on any other version.

Security rules (docs/HOW-IT-WORKS.md, "Four layers of control"):
  * This addon owns layer selection. The built-in NextLayer addon is disabled, so a
    connection we have not decided on (e.g. a ClientHello split across segments) can never
    fall through to a default "intercept/forward" decision.
  * Repoint: the upstream is always the SNI (TLS) or Host (plain HTTP) resolved by the proxy,
    never the IP the client connected to. Needs connection_strategy=lazy.
  * TLS: SNI checked at the ClientHello. No SNI / IP-literal SNI / not allowlisted -> closed
    without opening any upstream connection.
  * HTTP: Host checked on every request; inside intercepted TLS it must equal the SNI.
  * http-filter: on a filtered host, a request the Host check allowed is then matched on
    method + path (policy_core.HttpFilter) and refused with method-not-allowed /
    path-not-allowed. Passthrough connections are never decrypted, so never filtered. The
    action's own setup probe (policy_core.is_selftest_probe) is not filtered, and its body
    is dropped.
  * Upstream IP guard (review H1): every upstream connection (intercept, passthrough, plain
    HTTP) is resolved ONCE here, refused if any address is internal (loopback, link-local
    incl. IMDS, RFC 1918, CGNAT, ULA...), and pinned to the checked address so mitmproxy
    cannot re-resolve to something else.
  * Any exception in a hook fails closed.
  * Source (P2): container traffic is DNATed to a second transparent listener
    (``container_port`` in policy.json); a connection's source is the listener it arrived on,
    never inferred from its address (host traffic keeps its eth0 source after REDIRECT).

Every decision is written as one JSON line to the flow log.
"""

import asyncio
import json
import logging
import os
import re
import socket
import time
import traceback

from mitmproxy import ctx, http
from mitmproxy.net.tls import starts_like_tls_record
from mitmproxy.proxy import commands, events, layer, layers
from mitmproxy.proxy.layers.http import HTTPMode
from mitmproxy.proxy.layers.tls import ClientTLSLayer, ServerTLSLayer, parse_client_hello
from mitmproxy.version import VERSION

import policy_core as pc

PINNED_MITMPROXY_VERSION = "12.3.1"
CONFIG_PATH = os.environ.get("SAFER_RUNNER_POLICY", "/etc/safer-runner/policy.json")
MAX_PATH_LOG = 256

logger = logging.getLogger("safer_runner")
UPSTREAM_KILLED = re.compile(r"safer-runner: upstream blocked \(([a-z-]+)\)")


def addr(a):
    if not a:
        return None
    return f"{a[0]}:{a[1]}"


def safe_path(path):
    """Request path without the query string: query strings carry SAS tokens and other secrets."""
    return (path or "").split("?", 1)[0][:MAX_PATH_LOG]


class Block(layer.Layer):
    """Close the client connection without ever opening an upstream one."""

    def _handle_event(self, event):
        if isinstance(event, events.Start):
            if self.context.server.connected:
                yield commands.CloseConnection(self.context.server)
            yield commands.CloseConnection(self.context.client)


class ByteCounter:
    """Stream callable that counts body bytes without buffering them."""

    __slots__ = ("n",)

    def __init__(self):
        self.n = 0

    def __call__(self, data):
        self.n += len(data)
        return data


class DropBody(ByteCounter):
    """A ByteCounter that forwards nothing (for requests that must not carry a body)."""

    __slots__ = ()

    def __call__(self, data):
        self.n += len(data)
        return b""


def _no_decision(nextlayer):
    """Replacement for the built-in NextLayer hook: never decide anything."""
    return None


class SaferRunnerPolicy:
    def __init__(self):
        self.policy = None
        self.cfg = {}
        self.flowlog = None
        self.conns = {}  # client connection id -> state recorded at the outer layer decision
        self.pinned = {}  # server connection id -> (name, port) while connecting to the pinned IP
        self.container_port = None

    # ---------------------------------------------------------------- lifecycle

    def load(self, loader):
        if VERSION != PINNED_MITMPROXY_VERSION:
            # An error during startup makes mitmdump exit (ErrorCheck addon): fail closed.
            logger.error(f"safer-runner: mitmproxy {VERSION} != pinned {PINNED_MITMPROXY_VERSION}")
            return
        try:
            self.policy, self.cfg = pc.Policy.load(CONFIG_PATH)
            pc.selftest(self.policy)
            self.flowlog = open(self.cfg["flow_log"], "a", buffering=1)
        except Exception as e:  # noqa: BLE001
            logger.error(f"safer-runner: failed to load policy {CONFIG_PATH}: {e!r}")
            self.policy = None
            return
        builtin = ctx.master.addons.get("nextlayer")
        if builtin is None:
            logger.error("safer-runner: built-in nextlayer addon not found")
            self.policy = None
            return
        builtin.next_layer = _no_decision
        self.container_port = self.cfg.get("container_port")

    def source(self, client):
        """host | container: which listener the client connection arrived on.

        From the client's proxy mode (``transparent@127.0.0.1:<port>``), NOT client.sockname:
        in transparent mode sockname is the connection's original destination.
        """
        mode = getattr(client, "proxy_mode", None) if client is not None else None
        port = getattr(mode, "custom_listen_port", None)
        if self.container_port and port == self.container_port:
            return pc.SOURCE_CONTAINER
        return pc.SOURCE_HOST

    def running(self):
        if self.policy is None:
            logger.error("safer-runner: policy not loaded, refusing to run")
            return
        if ctx.options.connection_strategy != "lazy":
            logger.error("safer-runner: connection_strategy must be 'lazy' (repoint needs it)")
            return
        if ctx.master.addons.get("nextlayer").next_layer is not _no_decision:
            logger.error("safer-runner: built-in layer selection is still active")
            return
        if self.container_port and not any(
            str(m).endswith(f":{self.container_port}") for m in ctx.options.mode
        ):
            # container traffic would be classified as host (intercepted, no CA): say so
            logger.error(f"safer-runner: no proxy listener on the container port {self.container_port}")
            return
        self.emit(
            ev="start",
            ok=True,
            mode=self.policy.mode,
            mitmproxy=VERSION,
            allow=len(self.policy.allow_patterns),
            passthrough=self.policy.passthrough_patterns,
            deny=self.policy.deny_patterns,
            container_tls=self.policy.container_tls,
            container_port=self.container_port,
            http_filter_hosts=len(self.policy.http_filter.hosts),
            platform_auto_allowed=len(self.policy.http_filter.platform),
            pid=os.getpid(),
        )

    def emit(self, **kw):
        kw["ts"] = round(time.time(), 3)
        try:
            self.flowlog.write(json.dumps(kw, sort_keys=True, default=str) + "\n")
        except Exception:  # noqa: BLE001 - logging must never break traffic handling
            logger.warning("safer-runner: flow log write failed: " + traceback.format_exc())

    def _verdict(self, action):
        if action == "block":
            return pc.BLOCK if self.policy.enforce else pc.WOULD_BLOCK
        return {"intercept": pc.INTERCEPT, "passthrough": pc.PASSTHROUGH, "allow": pc.ALLOW}[action]

    # ---------------------------------------------------------------- layer selection

    def next_layer(self, nl):
        if nl.layer is not None:
            return
        try:
            self._next_layer(nl)
        except Exception:  # noqa: BLE001
            nl.layer = Block(nl.context)
            self.emit(ev="error", where="next_layer", error=traceback.format_exc(limit=3),
                      client=addr(nl.context.client.peername))

    def _repoint(self, c, name):
        """Send the upstream connection to `name` (resolved by the proxy), not the client's IP."""
        if c.server.connected:
            raise RuntimeError("server connected before the policy decision (connection_strategy?)")
        c.server.address = (name, c.server.address[1])

    def _next_layer(self, nl):
        c = nl.context
        client = addr(c.client.peername)
        source = self.source(c.client)
        state = self.conns.get(c.client.id)

        if state is not None:
            # Inner layer: the decrypted stream inside TLS we chose to intercept. Only HTTP is
            # spoken there (Host is enforced per request); anything else is closed.
            if state["kind"] == "intercept" and c.client.tls_established:
                nl.layer = layers.HttpLayer(c, HTTPMode.transparent)
            else:
                nl.layer = Block(c)
                self.emit(ev="tls", verdict=pc.BLOCK, reason="unexpected-inner-layer", layer="sni",
                          sni=state.get("name"), client=client, source=source)
            return

        if self.policy is None or c.client.transport_protocol != "tcp" or not c.server.address:
            nl.layer = Block(c)
            return

        data = nl.data_client()
        if len(data) < 3:
            return  # not enough to tell TLS from HTTP yet; nothing else will decide meanwhile
        dst = addr(c.server.address)

        if not starts_like_tls_record(data):
            # Plain text: only HTTP is supported. Host is enforced (and the upstream repointed)
            # per request in requestheaders(); a non-HTTP stream fails to parse and is closed.
            self.conns[c.client.id] = {"kind": "http", "dst": dst, "source": source}
            nl.layer = layers.HttpLayer(c, HTTPMode.transparent)
            return

        try:
            ch = parse_client_hello(data)
        except ValueError:
            nl.layer = Block(c)
            self.emit(ev="tls", verdict=pc.BLOCK, reason="invalid-clienthello", layer="sni",
                      dst=dst, client=client, source=source)
            return
        if ch is None:
            return  # ClientHello incomplete: wait for more data

        sni = pc.norm_host(ch.sni) or None
        d = self.policy.decide_tls(sni, source)
        verdict = self._verdict(d.action)
        record = dict(ev="tls", verdict=verdict, reason=d.reason, layer="sni", sni=sni, dst=dst,
                      client=client, source=source)

        if d.action == "block" and self.policy.enforce:
            nl.layer = Block(c)
            self.emit(**record)
            return

        if d.action == "intercept":
            self._repoint(c, sni)
            server_tls = ServerTLSLayer(c)
            server_tls.child_layer = ClientTLSLayer(c)
            nl.layer = server_tls
            self.conns[c.client.id] = {"kind": "intercept", "name": sni, "dst": dst, "source": source}
            self.emit(**record, repointed=True)
            return

        # passthrough (incl. container sni-only), or analyze-mode would-block: SNI-only, not
        # decrypted (no CA trust needed), repointed to the SNI when there is a usable name.
        repoint = bool(sni) and not pc.is_ip_literal(sni)
        if repoint:
            self._repoint(c, sni)
        nl.layer = layers.TCPLayer(c, ignore=True)
        self.conns[c.client.id] = {"kind": "passthrough", "name": sni, "dst": dst, "source": source}
        self.emit(**record, repointed=repoint, passthrough=True)

    # ---------------------------------------------------------------- HTTP

    def requestheaders(self, flow: http.HTTPFlow):
        try:
            self._requestheaders(flow)
        except Exception:  # noqa: BLE001
            self._refuse(flow, "internal-error", pc.norm_host(flow.request.host_header))
            self.emit(ev="error", where="requestheaders", error=traceback.format_exc(limit=3))

    def _refuse(self, flow, reason, host):
        flow.response = http.Response.make(
            403,
            f"safer-runner: egress to {host or '<no host>'} blocked ({reason})\n".encode(),
            {"content-type": "text/plain", "x-safer-runner": "blocked"},
        )

    def _requestheaders(self, flow):
        req = flow.request
        state = self.conns.get(flow.client_conn.id) or {}
        sni = state.get("name") if state.get("kind") == "intercept" else None
        host = pc.norm_host(req.host_header)
        others = [req.authority, req.headers.get("host")]
        d = self.policy.decide_http(req.host_header, others=others, method=req.method, sni=sni)
        probe = d.action == "allow" and pc.is_selftest_probe(host, req.method, req.path, state.get("dst"))
        f = self.policy.decide_filter(host, req.method, req.path) if d.action == "allow" and not probe else None
        if f is not None and f.action == "block":
            d = f  # http-filter: the host is allowed but this method/path is not
        verdict = self._verdict(d.action)
        meta = dict(
            ev="https" if sni else "http", verdict=verdict, reason=d.reason, layer="http",
            host=host or None, sni=sni, method=req.method, path=safe_path(req.path),
            dst=state.get("dst"), client=addr(flow.client_conn.peername),
            source=state.get("source") or self.source(flow.client_conn),
        )
        if f is not None:
            platform = f.rule == pc.FILTER_PLATFORM
            meta["filter"] = "platform" if platform else ("allow" if f.action == "allow" else "block")
            meta["filter_rule"] = None if platform else f.rule
        if d.action == "block" and self.policy.enforce:
            self._refuse(flow, d.reason, host)
            meta["status"] = 403
            self.emit(**meta)
            flow.metadata["safer_runner"] = dict(meta, logged=True)
            return

        # Repoint: the upstream is the name, never the client-chosen IP.
        target = sni or (host if host and not pc.is_ip_literal(host) else None)
        if target:
            req.host = target
        meta["repointed"] = bool(target)
        meta["req_counter"] = DropBody() if probe else ByteCounter()
        req.stream = meta["req_counter"]
        flow.metadata["safer_runner"] = meta

    def responseheaders(self, flow: http.HTTPFlow):
        meta = flow.metadata.get("safer_runner")
        if meta is not None and "resp_counter" not in meta:
            meta["resp_counter"] = ByteCounter()
            flow.response.stream = meta["resp_counter"]

    def response(self, flow: http.HTTPFlow):
        self._finish(flow)

    def error(self, flow: http.HTTPFlow):
        self._finish(flow, error=str(flow.error) if flow.error else "error")

    def _finish(self, flow, error=None):
        meta = flow.metadata.get("safer_runner")
        if meta is None or meta.get("logged"):
            return
        meta["logged"] = True
        rec = {k: v for k, v in meta.items() if k not in ("req_counter", "resp_counter", "logged")}
        rec["req_bytes"] = meta["req_counter"].n if "req_counter" in meta else 0
        rec["resp_bytes"] = meta["resp_counter"].n if "resp_counter" in meta else 0
        if flow.response is not None:
            rec["status"] = flow.response.status_code
        if flow.server_conn is not None and flow.server_conn.peername:
            rec["upstream"] = addr(flow.server_conn.peername)
        if error:
            rec["error"] = error[:200]
            killed = UPSTREAM_KILLED.search(error)
            if killed:  # server_connect refused the upstream: the request was blocked, not allowed
                rec["verdict"], rec["reason"] = pc.BLOCK, killed.group(1)
        self.emit(**rec)

    # ---------------------------------------------------------------- upstream IP guard

    async def server_connect(self, data):
        try:
            await self._server_connect(data)
        except Exception:  # noqa: BLE001
            data.server.error = "safer-runner: upstream blocked (internal-error)"
            self.emit(ev="error", where="server_connect", error=traceback.format_exc(limit=3),
                      client=addr(data.client.peername))

    async def _server_connect(self, data):
        s = data.server
        if self.policy is None:
            s.error = "safer-runner: upstream blocked (no-policy)"
            return
        name, port = s.address
        if pc.is_ip_literal(name):
            addrs = [name]  # not repointed (analyze-mode would-block on an IP): check what was dialled
        else:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(name, port, type=socket.SOCK_STREAM)
                addrs = [i[4][0] for i in infos]
            except OSError:
                addrs = []
        ip, reason = pc.pick_upstream(addrs)
        if reason:
            self.emit(ev="upstream", verdict=self._verdict("block"), reason=reason, layer="ip",
                      host=None if pc.is_ip_literal(name) else name, dst=addr((ip, port)) if ip else None,
                      resolved=addrs[:8], client=addr(data.client.peername), source=self.source(data.client))
            if self.policy.enforce:
                s.error = f"safer-runner: upstream blocked ({reason})"
                return
            if ip is None:
                return  # analyze, unresolvable: mitmproxy fails the connect itself
        if ip != name:
            # Pin: connect to the address just checked, not whatever a second lookup returns.
            if s.tls and s.sni is None:
                s.sni = name
            self.pinned[s.id] = s.address
            s.address = (ip, port)

    def _unpin(self, s):
        """Put the name back once connected: mitmproxy matches reusable connections by address."""
        orig = self.pinned.pop(s.id, None)
        if orig is not None:
            # Server.__setattr__ refuses address changes on an open connection; this is the
            # same name the connection was opened for, so bypass it.
            object.__setattr__(s, "address", orig)

    def server_connect_error(self, data):
        self._unpin(data.server)

    # ---------------------------------------------------------------- connections

    def server_connected(self, data):
        s = data.server
        self._unpin(s)
        self.emit(ev="server-connect", address=addr(s.address), peername=addr(s.peername),
                  client=addr(data.client.peername), source=self.source(data.client))

    def client_disconnected(self, client):
        self.conns.pop(client.id, None)

    def tls_failed_client(self, data):
        client = data.context.client
        self.emit(ev="tls-client-fail", sni=client.sni, client=addr(client.peername),
                  source=self.source(client), error=str(data.conn.error)[:200])

    def tls_failed_server(self, data):
        self.emit(ev="tls-server-fail", sni=data.conn.sni, address=addr(data.conn.address),
                  client=addr(data.context.client.peername), source=self.source(data.context.client),
                  error=str(data.conn.error)[:200])


addons = [SaferRunnerPolicy()]
