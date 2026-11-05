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
 * Every log line labels itself (ALLOW / BLOCK / WOULD_BLOCK) through its block's own `log`
 * format, so the report parser never has to infer a verdict (src/parsers/dns-parser.ts).
 */

import { validatePattern, type Mode } from '../policy';

export const DNS_LISTEN = '127.0.0.1';
/** Upper bound on positive-answer cache TTL (same as dnsmasq's max-cache-ttl before). */
export const CACHE_TTL = 3600;

export interface CorefileOptions {
  mode: Mode;
  /** proxy allow + passthrough patterns (already validated by buildPolicyConfig) */
  allow: string[];
  /** names always refused (the risky-subdomain denylist) */
  deny: string[];
  upstreams: string[];
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

function forwardBlock(label: string, upstreams: string[], view?: string): string {
  return [
    `.:53 {`,
    `  bind ${DNS_LISTEN}`,
    ...(view ? [`  view allow {`, `    expr ${view}`, `  }`] : []),
    `  metadata`,
    `  log . "${label === 'ALLOW' ? LOG_ALLOW : logLine(label)}"`,
    `  errors`,
    `  cache ${CACHE_TTL} {`,
    `    serve_stale 1h`,
    `  }`,
    `  forward . ${upstreams.join(' ')}`,
    `}`
  ].join('\n');
}

export function buildCorefile(o: CorefileOptions): string {
  if (!o.upstreams.length) throw new Error('no upstream DNS servers');
  for (const u of o.upstreams) {
    if (!/^[0-9a-f.:]+$/i.test(u)) throw new Error(`invalid upstream DNS server: '${u}'`);
  }
  const view = allowExpr(o.allow, o.deny);
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
  return `${header}${forwardBlock('ALLOW', o.upstreams, view)}\n${deny}\n`;
}
