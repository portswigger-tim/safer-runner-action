/**
 * v2 hostname policy: builds the policy.json the proxy addon enforces, and mirrors the
 * addon's pattern matching (proxy/policy_core.py) for the report and DNS config.
 *
 * Pattern semantics (identical in Python; both are checked against proxy/test-vectors.json):
 *  - `example.com`     -> exactly example.com (no subdomains)
 *  - `*.example.com`   -> any subdomain of example.com (not the apex)
 *  - `a-*.example.com` -> `*` matches within ONE label; the rest must match exactly
 *
 * Input shorthand (expanded before validation, never reaches the addon or the Corefile):
 *  - `.example.com`    -> `example.com` + `*.example.com` (the apex and all subdomains)
 */

import { DANGEROUS_BROAD_DOMAINS } from './parsers/github-parser';
import { RISKY_GITHUB_SUBDOMAINS, parseAllowedDomains } from './config/dns-config-builder';
import { FLOW_LOG } from './constants';

export type Mode = 'analyze' | 'enforce';

/**
 * How the proxy treats TLS from containers (P2). `sni-only`: allowlisted names are passed
 * through by SNI (repointed, never decrypted - no CA needed in the container). `intercept`:
 * same as the host (needs the CA in every container; the runtime shim that injects it is P3).
 */
export type ContainerTls = 'sni-only' | 'intercept';

/**
 * Multi-tenant front doors: one TLS front end serves every tenant and routes by Host, so an
 * SNI-only check would allow fronting to any tenant. Under container sni-only these stay
 * intercepted for containers in enforce. Mirrors FRONT_DOORS in proxy/policy_core.py (both
 * are checked against proxy/test-vectors.json).
 */
export const FRONT_DOORS = [
  '*.blob.core.windows.net',
  '*.dfs.core.windows.net',
  '*.file.core.windows.net',
  '*.queue.core.windows.net',
  '*.table.core.windows.net',
  '*.web.core.windows.net'
];

/**
 * Hosts that MUST be passed through (SNI-only, never decrypted). Empirical (P0 spike): the
 * Go hosted-compute agent loads system roots at boot and can never trust a CA added later,
 * and it runs as the same uid as job steps, so it cannot be exempted by uid instead.
 */
export const MANDATORY_PASSTHROUGH = ['hosted-compute-*.githubapp.com'];

export interface PolicyConfig {
  version: 1;
  mode: Mode;
  allow: string[];
  passthrough: string[];
  deny: string[];
  flow_log: string;
  container_tls: ContainerTls;
  /** Proxy listener that only receives container traffic (the addon classifies by it). */
  container_port: number;
}

const LABEL = /^[a-z0-9_*]([a-z0-9_*-]*[a-z0-9_*])?$/;

export function normHost(host: string | null | undefined): string {
  if (!host) return '';
  let h = String(host).trim().toLowerCase();
  if (h.startsWith('[')) {
    const end = h.indexOf(']');
    return end > 0 ? h.slice(1, end) : h;
  }
  if ((h.match(/:/g) || []).length === 1) h = h.slice(0, h.lastIndexOf(':'));
  return h.replace(/\.+$/, '');
}

export function isIpLiteral(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

/** Return the normalised pattern, or throw with a reason. */
export function validatePattern(pattern: string): string {
  const p = normHost(pattern);
  if (!p || !p.includes('.')) throw new Error(`not a domain pattern: '${pattern}'`);
  if (isIpLiteral(p)) throw new Error(`IP literals are not allowed in patterns: '${pattern}'`);
  const labels = p.split('.');
  if (!labels.every(l => LABEL.test(l))) throw new Error(`invalid domain pattern: '${pattern}'`);
  if (labels.slice(-2).some(l => l.includes('*'))) {
    throw new Error(`wildcard too broad (in the registrable part): '${pattern}'`);
  }
  if (p.startsWith('*.') && p.slice(2).includes('*')) {
    throw new Error(`only one wildcard form per pattern: '${pattern}'`);
  }
  return p;
}

/**
 * Expand the `.host` shorthand into `host` + `*.host`; anything else is returned as is. The
 * result still has to pass validatePattern.
 */
export function expandPattern(entry: string): string[] {
  const e = entry.trim();
  if (e.startsWith('.') && !e.startsWith('..')) return [e.slice(1), `*${e}`];
  return [e];
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function compilePattern(pattern: string): RegExp {
  const p = validatePattern(pattern);
  let body: string;
  if (p.startsWith('*.')) {
    body = '(?:[a-z0-9_-]+\\.)+' + escapeRegex(p.slice(2));
  } else if (p.includes('*')) {
    body = p.split('*').map(escapeRegex).join('[a-z0-9_-]*');
  } else {
    body = escapeRegex(p);
  }
  return new RegExp('^' + body + '$');
}

export function matchesAny(host: string, compiled: RegExp[]): boolean {
  const h = normHost(host);
  return h !== '' && compiled.some(c => c.test(h));
}

/** A pattern that would allow a whole shared namespace (anyone can register a sibling name). */
export function isDangerouslyBroad(pattern: string): boolean {
  const base = pattern.startsWith('*.') ? pattern.slice(2) : pattern;
  return DANGEROUS_BROAD_DOMAINS.has(base);
}

export interface PolicyBuildOptions {
  mode: Mode;
  githubDomains: string[];
  allowedDomains: string;
  passthroughDomains: string;
  blockRiskySubdomains: boolean;
  containerTls: ContainerTls;
  containerPort: number;
}

export interface PolicyBuildResult {
  config: PolicyConfig;
  /** Problems with user input (entries dropped); the caller surfaces them. */
  warnings: string[];
}

function uniq(xs: string[]): string[] {
  return Array.from(new Set(xs));
}

/** Validate user patterns, dropping (and reporting) anything invalid or dangerously broad. */
function cleanUserPatterns(raw: string, inputName: string, warnings: string[]): string[] {
  const out: string[] = [];
  for (const entry of parseAllowedDomains(raw).flatMap(expandPattern)) {
    try {
      const p = validatePattern(entry);
      if (isDangerouslyBroad(p)) {
        warnings.push(`${inputName}: '${entry}' is a shared multi-tenant namespace and was ignored`);
        continue;
      }
      out.push(p);
    } catch (e) {
      warnings.push(`${inputName}: ${(e as Error).message} - ignored`);
    }
  }
  return out;
}

export function buildPolicyConfig(opts: PolicyBuildOptions): PolicyBuildResult {
  const warnings: string[] = [];
  const github: string[] = [];
  for (const d of opts.githubDomains) {
    try {
      github.push(validatePattern(d));
    } catch {
      // the meta/static lists are normalised already; skip anything odd rather than fail
    }
  }
  const user = cleanUserPatterns(opts.allowedDomains, 'allowed-domains', warnings);
  const passthrough = uniq([
    ...MANDATORY_PASSTHROUGH,
    ...cleanUserPatterns(opts.passthroughDomains, 'passthrough-domains', warnings)
  ]);
  const deny = opts.blockRiskySubdomains ? [...RISKY_GITHUB_SUBDOMAINS] : [];

  return {
    config: {
      version: 1,
      mode: opts.mode,
      allow: uniq([...github, ...user]),
      passthrough,
      deny,
      flow_log: FLOW_LOG,
      container_tls: opts.containerTls,
      container_port: opts.containerPort
    },
    warnings
  };
}

/**
 * Domains dnsmasq must forward for a set of patterns. dnsmasq's server=/d/ matches d and
 * all subdomains and has no mid-label wildcard, so a pattern maps to the suffix after its
 * last wildcard label (the proxy, not DNS, enforces the exact pattern).
 */
export function dnsDomainsFor(patterns: string[]): string[] {
  const out: string[] = [];
  for (const p of patterns) {
    const labels = p.split('.');
    let i = labels.length;
    while (i > 0 && !labels[i - 1].includes('*')) i--;
    out.push(labels.slice(i).join('.'));
  }
  return uniq(out);
}
