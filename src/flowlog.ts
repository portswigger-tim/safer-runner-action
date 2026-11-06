/**
 * Reader for the proxy's JSONL flow log (written by proxy/policy.py).
 */

import * as fs from 'fs';

export interface FlowRecord {
  ts: number;
  ev: string;
  verdict?: 'INTERCEPT' | 'PASSTHROUGH' | 'ALLOW' | 'BLOCK' | 'WOULD_BLOCK';
  reason?: string;
  /** sni: TLS name check; http: Host or http-filter check; ip: the upstream IP guard (proxy/policy.py) */
  layer?: 'sni' | 'http' | 'ip';
  sni?: string | null;
  host?: string | null;
  method?: string;
  path?: string;
  status?: number;
  req_bytes?: number;
  resp_bytes?: number;
  client?: string;
  dst?: string;
  upstream?: string;
  repointed?: boolean;
  passthrough?: boolean;
  error?: string;
  /** http-filter decision on a filtered host: `platform` = allowed by the built-in platform list */
  filter?: 'allow' | 'platform' | 'block';
  /** the winning http-filter path pattern; null when none matched or a platform entry allowed it */
  filter_rule?: string | null;
  /** which proxy listener the connection arrived on (P2); absent in older logs = host */
  source?: 'host' | 'container';
  [key: string]: unknown;
}

export function parseFlowLog(text: string): FlowRecord[] {
  const out: FlowRecord[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as FlowRecord);
    } catch {
      // a partially written last line
    }
  }
  return out;
}

/** Records plus the byte offset each one starts at (to tell which phase of the job wrote it). */
export function parseFlowLogWithOffsets(text: string): { records: FlowRecord[]; offsets: number[] } {
  const records: FlowRecord[] = [];
  const offsets: number[] = [];
  let at = 0;
  for (const line of text.split('\n')) {
    const start = at;
    at += Buffer.byteLength(line, 'utf8') + 1;
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line) as FlowRecord);
      offsets.push(start);
    } catch {
      // a partially written last line
    }
  }
  return { records, offsets };
}

export function readFlowLog(file: string, fromByte = 0): FlowRecord[] {
  if (!fs.existsSync(file)) return [];
  const buf = fs.readFileSync(file);
  return parseFlowLog(buf.subarray(Math.min(fromByte, buf.length)).toString('utf8'));
}

export function flowLogSize(file: string): number {
  return fs.existsSync(file) ? fs.statSync(file).size : 0;
}

/** The IP part of an `ip:port` string. */
export function ipOf(hostport: string | undefined | null): string {
  if (!hostport) return '';
  const i = hostport.lastIndexOf(':');
  return i > 0 ? hostport.slice(0, i) : hostport;
}
