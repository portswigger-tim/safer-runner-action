/** Parser for the kernel LOG lines our filter chains write (firewall.ts), via rsyslog to firewall.log. */

export interface FirewallEvent {
  prefix: string;
  proto: string;
  /** source address: a container's address for the container prefixes */
  src: string;
  dst: string;
  dport: string;
  /** source port: a resent SYN keeps it, so it tells one connection attempt from the next */
  sport?: string;
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
      sport: field('SPT'),
      uid: field('UID')
    });
  }
  return out;
}

export interface FirewallSummary {
  /** one row per (prefix, proto, destination, uid), with its connection attempts */
  rows: { e: FirewallEvent; n: number }[];
  rejected: number;
  logged: number;
}

/**
 * Connection attempts in some LOG lines: one per source port. An unanswered SYN (analyze lets it
 * through) is resent from the same port and logged each time; a line with no port counts once.
 */
export function attempts(events: FirewallEvent[]): number {
  const ports = new Set<string>();
  let unknown = 0;
  for (const e of events) {
    if (e.sport) ports.add(e.sport);
    else unknown++;
  }
  return ports.size + unknown;
}

export function firewallSummary(events: FirewallEvent[]): FirewallSummary {
  const seen = new Map<string, FirewallEvent[]>();
  for (const e of events) {
    const k = `${e.prefix} ${e.proto} ${e.dst}:${e.dport} uid ${e.uid}`;
    seen.set(k, [...(seen.get(k) ?? []), e]);
  }
  const rows = Array.from(seen.values(), es => ({ e: es[0], n: attempts(es) }));
  const rejected = rows.filter(r => REJECT_PREFIXES.has(r.e.prefix)).length;
  return { rows, rejected, logged: rows.length - rejected };
}
