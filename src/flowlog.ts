/**
 * Reader for the proxy's JSONL flow log (written by proxy/policy.py).
 */

import * as fs from 'fs';

export interface FlowRecord {
  ts: number;
  ev: string;
  verdict?: 'INTERCEPT' | 'PASSTHROUGH' | 'ALLOW' | 'BLOCK' | 'WOULD_BLOCK';
  reason?: string;
  layer?: 'sni' | 'http';
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
