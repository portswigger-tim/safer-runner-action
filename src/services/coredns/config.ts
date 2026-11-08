/**
 * Corefile builder for the CoreDNS resolver (replaces dnsmasq). Pure functions, no I/O.
 *
 * enforce: one server block selected by a `view` expression that mirrors the proxy's pattern
 * set exactly (src/policy.ts compilePattern / proxy/policy_core.py compile_pattern; all three
 * are checked against proxy/test-vectors.json), forwarding to the upstreams; and a catch-all
 * block that answers NXDOMAIN locally. So a subdomain of an exact entry
 * (`<secret>.example.com`) is refused on the host and never forwarded: default-deny, fail
 * closed (a view that matches nothing denies; a Corefile that doesn't parse means nothing
 * listens on :53).
 *
 * analyze: both blocks forward. The second one labels what enforce would refuse.
 *
 * /etc/hosts names (+ the VM's hostname) are routed to the allow block and answered there by
 * the `hosts` plugin (it runs after `template` in CoreDNS's plugin order, so it can't live in
 * the deny block).
 *
 * Every log line labels itself (ALLOW / BLOCK / WOULD_BLOCK) through its block's own `log`
 * format, so the report parser never has to infer a verdict (src/services/coredns/log.ts).
 */

import * as net from 'net';
import { COREDNS_BIN, COREFILE, DNS_LOG, DNS_UNIT, ETC_DIR } from '../../constants';
import { validatePattern, type Mode } from '../../policy';
import type { Rendered } from '../../system/types';
import { HARDENING } from '../../system/unit';

export const DNS_LISTEN = '127.0.0.1';
/** Upper bound on positive-answer cache TTL (same as dnsmasq's max-cache-ttl before). */
export const CACHE_TTL = 3600;

/**
 * Local names answered from /etc/hosts (the `hosts` plugin), as dnsmasq did: containers (via
 * Docker's embedded resolver) and DNS clients like dig resolve them through us, not nsswitch.
 * Never forwarded, so no exfil channel. `names` routes them to the allow block (the view is
 * static, so a name added to /etc/hosts later is not routed - that needs root anyway).
 */
export interface LocalHosts {
  file: string;
  names: string[];
  /** extra `ip name` entries, e.g. the VM's own hostname when /etc/hosts lacks it (AWS) */
  inline: { ip: string; name: string }[];
}

export interface CorefileOptions {
  mode: Mode;
  /** proxy allow + passthrough patterns (already validated by buildPolicyConfig) */
  allow: string[];
  /** names always refused (the risky-subdomain denylist) */
  deny: string[];
  upstreams: string[];
  hosts?: LocalHosts;
}

const LOCAL_NAME = /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$/;

/** Hostnames from an /etc/hosts file (lower-cased, unique; comments and odd names skipped). */
export function parseHostsNames(text: string): string[] {
  const out = new Set<string>();
  for (const raw of text.split('\n')) {
    const fields = raw.replace(/#.*/, '').trim().split(/\s+/);
    if (fields.length < 2 || net.isIP(fields[0]) === 0) continue;
    for (const n of fields.slice(1)) {
      const name = n.toLowerCase().replace(/\.$/, '');
      if (LOCAL_NAME.test(name)) out.add(name);
    }
  }
  return Array.from(out);
}

const LOG_ALLOW = '{remote} ALLOW {type} {name} {rcode} upstream={/forward/upstream} {duration}';
const logLine = (label: string) => `{remote} ${label} {type} {name} {rcode} upstream={/forward/upstream} {duration}`;

/** expr string literal for a DNS name (CoreDNS's name() is lower-case and fully qualified). */
function lit(s: string, allowed = /^[a-z0-9_.-]+$/): string {
  // validatePattern restricts the charset to [a-z0-9_*.-]; refuse anything that could break
  // out of the quoted literal (a quote, a backslash, whitespace), whatever the caller passed
  if (!allowed.test(s)) throw new Error(`unsafe DNS name for the Corefile: '${s}'`);
  return `'${s}'`;
}

function regexFor(globPattern: string): string {
  const body = globPattern
    .split('*')
    .map(part => part.replace(/\./g, '[.]'))
    .join('[a-z0-9_-]*');
  return `^${body}[.]$`;
}

/**
 * The expr clause for a set of patterns: exact names batched into one `in [...]`, `*.x` as
 * `endsWith '.x.'`, a single-label glob as an anchored regex.
 */
export function patternsExpr(patterns: string[]): string {
  const exact: string[] = [];
  const terms: string[] = [];
  for (const raw of patterns) {
    const p = validatePattern(raw);
    if (p.startsWith('*.')) {
      terms.push(`name() endsWith ${lit('.' + p.slice(2) + '.')}`);
    } else if (p.includes('*')) {
      terms.push(`name() matches ${lit(regexFor(p), /^\^[a-z0-9_.\[\]*-]+\$$/)}`);
    } else {
      exact.push(lit(p + '.'));
    }
  }
  if (exact.length) terms.unshift(`name() in [${Array.from(new Set(exact)).join(', ')}]`);
  return terms.length ? terms.join(' || ') : 'false';
}

/** The full `view` expression: allowed and not denied. */
export function allowExpr(allow: string[], deny: string[]): string {
  const a = `(${patternsExpr(allow)})`;
  return deny.length ? `${a} && !(${patternsExpr(deny)})` : a;
}

function hostsLines(h: LocalHosts): string[] {
  if (!/^\/[A-Za-z0-9_./-]+$/.test(h.file)) throw new Error(`invalid hosts file path: '${h.file}'`);
  const inline = h.inline.map(({ ip, name }) => {
    if (net.isIP(ip) === 0 || !LOCAL_NAME.test(name)) throw new Error(`invalid hosts entry: '${ip} ${name}'`);
    return `    ${ip} ${name}`;
  });
  // fallthrough: allowlisted names not in the file go on to forward
  return [`  hosts ${h.file} {`, ...inline, `    fallthrough`, `  }`];
}

/** dns-servers order matters: the first is the primary, the rest are tried in order after it. */
function forwardLines(upstreams: string[]): string[] {
  if (upstreams.length === 1) return [`  forward . ${upstreams[0]}`];
  return [`  forward . ${upstreams.join(' ')} {`, `    policy sequential`, `  }`];
}

function forwardBlock(label: string, upstreams: string[], view?: string, hosts?: LocalHosts): string {
  return [
    `.:53 {`,
    `  bind ${DNS_LISTEN}`,
    ...(view ? [`  view allow {`, `    expr ${view}`, `  }`] : []),
    `  metadata`,
    `  log . "${label === 'ALLOW' ? LOG_ALLOW : logLine(label)}"`,
    `  errors`,
    ...(hosts ? hostsLines(hosts) : []),
    `  cache ${CACHE_TTL} {`,
    `    serve_stale 1h`,
    `  }`,
    ...forwardLines(upstreams),
    `}`
  ].join('\n');
}

export function buildCorefile(o: CorefileOptions): string {
  if (!o.upstreams.length) throw new Error('no upstream DNS servers');
  for (const u of o.upstreams) {
    if (!/^[0-9a-f.:]+$/i.test(u)) throw new Error(`invalid upstream DNS server: '${u}'`);
  }
  let view = allowExpr(o.allow, o.deny);
  const local = o.hosts
    ? Array.from(new Set([...o.hosts.names, ...o.hosts.inline.map(e => e.name)].map(n => n.toLowerCase())))
    : [];
  if (local.length) {
    view = `(${view}) || name() in [${local.map(n => lit(n + '.', /^[a-z0-9_.-]+$/)).join(', ')}]`;
  }
  const header =
    `# safer-runner CoreDNS resolver (${o.mode}). Generated - do not edit.\n` +
    '# Blocks are tried in order: the first whose view matches answers the query.\n';
  const deny =
    o.mode === 'enforce'
      ? [
          `.:53 {`,
          `  bind ${DNS_LISTEN}`,
          `  log . "{remote} BLOCK {type} {name} {rcode}"`,
          `  errors`,
          `  template ANY ANY {`,
          `    rcode NXDOMAIN`,
          `  }`,
          `}`
        ].join('\n')
      : forwardBlock('WOULD_BLOCK', o.upstreams);
  return `${header}${forwardBlock('ALLOW', o.upstreams, view, o.hosts)}\n${deny}\n`;
}

export interface CoreDnsFacts extends CorefileOptions {
  /** the resolver's own (random) system user */
  user: string;
}

/**
 * Everything CoreDNS needs on disk, and its unit: as the DNS user with only CAP_NET_BIND_SERVICE
 * (for :53). stdout - the `log` plugin - is appended by systemd to the world-readable DNS log the
 * report reads; the log is pre-created root-owned 0644, and systemd's append keeps that mode.
 */
export function render(f: CoreDnsFacts): Rendered {
  return {
    inert: [
      { kind: 'dir', path: ETC_DIR, mode: '0755', owner: 'root:root' },
      { kind: 'file', path: COREFILE, content: buildCorefile(f), mode: '0644', owner: 'root:root' },
      { kind: 'touch', path: DNS_LOG, mode: '0644', owner: 'root:root' }
    ],
    unit: {
      unit: DNS_UNIT,
      description: 'safer-runner DNS resolver (CoreDNS)',
      user: f.user,
      props: [
        'AmbientCapabilities=CAP_NET_BIND_SERVICE',
        'CapabilityBoundingSet=CAP_NET_BIND_SERVICE',
        ...HARDENING,
        `StandardOutput=append:${DNS_LOG}`,
        `StandardError=append:${DNS_LOG}`
      ],
      argv: [COREDNS_BIN, '-conf', COREFILE]
    }
  };
}
