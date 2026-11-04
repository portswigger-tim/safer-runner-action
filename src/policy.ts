/**
 * v2 hostname policy: builds the policy.json the proxy addon enforces, and mirrors the
 * addon's pattern matching (proxy/policy_core.py) for the report and DNS config.
 *
 * Pattern semantics (identical in Python; both are checked against proxy/test-vectors.json):
 *  - `example.com`     -> example.com and any subdomain
 *  - `*.example.com`   -> any subdomain of example.com (not the apex)
 *  - `a-*.example.com` -> `*` matches within ONE label; the rest must match exactly
 */

import { DANGEROUS_BROAD_DOMAINS } from './parsers/github-parser';
import { RISKY_GITHUB_SUBDOMAINS, parseAllowedDomains } from './config/dns-config-builder';
import { FLOW_LOG } from './constants';

export type Mode = 'analyze' | 'enforce';

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
    body = '(?:[a-z0-9_-]+\\.)*' + escapeRegex(p);
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
  for (const entry of parseAllowedDomains(raw)) {
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
      flow_log: FLOW_LOG
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
