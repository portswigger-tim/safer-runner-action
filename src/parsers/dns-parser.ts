/**
 * CoreDNS query log parser. Each server block's `log` format labels its own lines
 * (src/config/corefile-builder.ts), so a policy refusal is never confused with an upstream
 * NXDOMAIN (a typo), and every query type is seen (dnsmasq's parser only chained A queries):
 *
 *   [INFO] 127.0.0.1:41452 ALLOW A github.com. NOERROR upstream=9.9.9.9:53 0.0086s
 *   [INFO] 127.0.0.1:39637 BLOCK TXT s3cr3t.example.com. NXDOMAIN
 *   [INFO] 127.0.0.1:51924 WOULD_BLOCK A example.org. NOERROR upstream=- 0.0001s   (analyze)
 */

import * as fs from 'fs';

export type DnsVerdict = 'ALLOW' | 'BLOCK' | 'WOULD_BLOCK';

export interface DnsQuery {
  verdict: DnsVerdict;
  client: string;
  type: string;
  /** lower-case, no trailing dot */
  name: string;
  rcode: string;
}

// anchored on the plugin's own prefix: a query name can't inject a second verdict
const LINE = /^\[INFO\] (\S+) (ALLOW|BLOCK|WOULD_BLOCK) (\S+) (\S+) (\S+)/;

export function parseDnsLog(text: string): DnsQuery[] {
  const out: DnsQuery[] = [];
  for (const line of text.split('\n')) {
    const m = LINE.exec(line);
    if (!m) continue;
    out.push({
      client: m[1],
      verdict: m[2] as DnsVerdict,
      type: m[3],
      name: m[4].toLowerCase().replace(/\.$/, ''),
      rcode: m[5]
    });
  }
  return out;
}

/** Names the resolver refused (enforce) or would have refused (analyze), first-seen order. */
export function refusedNames(queries: DnsQuery[]): string[] {
  return Array.from(new Set(queries.filter(q => q.verdict !== 'ALLOW').map(q => q.name)));
}

export function readRefusedNames(file: string): string[] {
  try {
    return refusedNames(parseDnsLog(fs.readFileSync(file, 'utf8')));
  } catch {
    return [];
  }
}
