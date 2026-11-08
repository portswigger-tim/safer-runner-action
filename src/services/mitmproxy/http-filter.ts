/** The http-filter part of the report: refused requests, and the suggested filter as YAML. */

import { Document, Pair, Scalar, YAMLMap, stringify } from 'yaml';
import type { FlowRecord } from '../../flowlog';
import { methodLabel } from '../../report/redact';
import { DENIED, FILTER_REASONS, allowedRequests, blockedName, type AllowedRequest } from './flows';

export interface FilterBlock {
  /** redacted like any refused name */
  host: string;
  /** a standard method, or an opaque label for any other (src/report/redact.ts) */
  method: string;
  reason: string;
  verdict: string;
  tries: number;
}

export interface HttpFilterRule {
  /** path pattern as written in `http-filter` (no leading `/`; `*` spans any depth) */
  path: string;
  /** allowed methods; empty = NONE */
  methods: string[];
}

export interface HttpFilterSuggestion {
  hosts: { host: string; rules: HttpFilterRule[] }[];
  /** requests the suggestion was built from */
  requests: number;
  rules: number;
  /** sensitive write endpoints kept path-specific */
  specific: number;
  /** a write rule had to start with `*`: generalised heavily, review it */
  coarse: boolean;
}

export interface HttpFilterReport {
  /** requests the filter refused (enforce) or would refuse (analyze) */
  blocks: FilterBlock[];
  /** a whole `http-filter` from the job's observed traffic (level B: read/write split); undefined: none built */
  suggestion?: HttpFilterSuggestion;
}

/** Builds the suggestion from the allowed requests (src/report/suggest.ts); undefined: none. */
export type Suggester = (requests: AllowedRequest[]) => HttpFilterSuggestion | undefined;

function isFilterBlock(r: FlowRecord): boolean {
  return DENIED.has(r.verdict) && FILTER_REASONS.has(r.reason ?? '');
}

/**
 * The http-filter part of the report: refused requests (host, method and why; never the path,
 * which the sender chose and can carry data whatever its shape), and a suggested `http-filter`
 * built by `suggest` from allowed traffic (proxy/suggest.py: observe → split reads from writes →
 * template writes → union methods; design: "Suggested http-filter (report)"). Advisory: never
 * applied. Without `suggest`, no suggestion.
 */
export function summarizeHttpFilter(records: FlowRecord[], suggest?: Suggester): HttpFilterReport {
  const byKey = new Map<string, FilterBlock>();
  for (const r of records) {
    if ((r.ev !== 'https' && r.ev !== 'http') || !isFilterBlock(r)) continue;
    const b: FilterBlock = {
      host: blockedName(r.host || r.sni || '(no host)'),
      method: methodLabel(r.method),
      reason: r.reason as string,
      verdict: r.verdict as string,
      tries: 0
    };
    const key = [b.host, b.method, b.reason].join(' ');
    const row = byKey.get(key) ?? b;
    row.tries++;
    byKey.set(key, row);
  }
  return {
    blocks: [...byKey.values()].sort((a, b) => b.tries - a.tries || a.host.localeCompare(b.host)),
    suggestion: suggest?.(allowedRequests(records))
  };
}

/**
 * The suggestion as the `http-filter` input's value, written by the `yaml` library that reads the
 * input (inputs.ts parseHttpFilter), so a pasted suggestion reads back as printed. Names, path
 * segments and methods are also checked before this (proxy/suggest.py, src/report/suggest.ts).
 */
export function httpFilterValue(s: HttpFilterSuggestion): string {
  const hosts = new YAMLMap();
  for (const h of s.hosts) {
    const rules = new YAMLMap();
    for (const r of h.rules) {
      // path patterns always in double quotes: `*` and `*/x` cannot be plain YAML
      const path = new Scalar(r.path);
      path.type = Scalar.QUOTE_DOUBLE;
      rules.add(new Pair(path, new Scalar(r.methods.length ? r.methods.join(', ') : 'NONE')));
    }
    hosts.add(new Pair(new Scalar(h.host), rules));
  }
  const doc = new Document();
  doc.contents = hosts;
  return doc.toString({ lineWidth: 0 });
}

/** The suggestion as an `http-filter:` input block. */
export function httpFilterYaml(s: HttpFilterSuggestion): string {
  return stringify({ 'http-filter': httpFilterValue(s) }, { blockQuote: 'literal', lineWidth: 0 }).replace(/\n$/, '');
}
