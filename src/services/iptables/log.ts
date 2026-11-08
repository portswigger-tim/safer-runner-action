/** Parser for the kernel LOG lines our filter chains write (firewall.ts), via rsyslog to firewall.log. */

export interface FirewallEvent {
  prefix: string;
  proto: string;
  /** source address: a container's address for the container prefixes */
  src: string;
  dst: string;
  dport: string;
  uid: string;
}

/** Container egress (FORWARD via DOCKER-USER) firewall prefixes. */
export const CONTAINER_PREFIXES = new Set(['SaferRunner-CDrop', 'SaferRunner-CEgress']);
const REJECT_PREFIXES = new Set(['SaferRunner-Drop', 'SaferRunner-CDrop']);

/** Parse kernel LOG lines written by our filter chain (see firewall.ts). */
export function parseFirewallLog(text: string): FirewallEvent[] {
  const out: FirewallEvent[] = [];
  for (const line of text.split('\n')) {
    const m = line.match(/(SaferRunner-\w+):/);
    if (!m) continue;
    const field = (k: string) => line.match(new RegExp(`\\b${k}=(\\S*)`))?.[1] ?? '';
    out.push({
      prefix: m[1],
      proto: field('PROTO'),
      src: field('SRC'),
      dst: field('DST'),
      dport: field('DPT'),
      uid: field('UID')
    });
  }
  return out;
}

export interface FirewallSummary {
  /** one row per (prefix, proto, destination, uid), with its packet count */
  rows: { e: FirewallEvent; n: number }[];
  rejected: number;
  logged: number;
}

export function firewallSummary(events: FirewallEvent[]): FirewallSummary {
  const seen = new Map<string, { e: FirewallEvent; n: number }>();
  for (const e of events) {
    const k = `${e.prefix} ${e.proto} ${e.dst}:${e.dport} uid ${e.uid}`;
    seen.set(k, { e, n: (seen.get(k)?.n ?? 0) + 1 });
  }
  const rows = Array.from(seen.values());
  const rejected = rows.filter(r => REJECT_PREFIXES.has(r.e.prefix)).length;
  return { rows, rejected, logged: rows.length - rejected };
}
