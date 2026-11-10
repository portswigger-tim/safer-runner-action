/**
 * The firewall's part of the job summary: connections that went around the proxy (only TCP 80/443
 * is proxied), from the host filter chain's LOG lines. The container chain's lines are reported
 * with their container (services/docker/containers.ts).
 */

import { CONTAINER_PREFIXES, firewallSummary, type FirewallEvent } from './log';
import { code } from '../../report/markdown';
import { emptySection, type BlockedRow, type ReportContext, type Section } from '../../report/section';

export interface FirewallObserved {
  events: FirewallEvent[];
}

const PORT_NAMES: Record<string, string> = {
  '22': 'SSH',
  '25': 'SMTP',
  '53': 'DNS',
  '80': 'HTTP',
  '123': 'NTP',
  '443': 'HTTPS',
  '853': 'DNS over TLS',
  '3128': 'HTTP proxy',
  '8080': 'HTTP-alt',
  '9418': 'git'
};

/** The LOG prefix without `SaferRunner-`: the word firewall.log has on the line. */
export const prefixWord = (prefix: string) => prefix.replace(/^SaferRunner-/, '');

/** `198.51.100.7:22` TCP · SSH, and who sent it (`dst` is the address and port). */
export function destination(dst: string, dport: string, proto: string, from: string): string {
  return [`${code(dst)} ${proto}`, PORT_NAMES[dport], from].filter(Boolean).join(' · ');
}

export function report(o: FirewallObserved, _ctx: ReportContext): Section {
  // container firewall events are reported in the container part, with their source
  const fw = firewallSummary(o.events.filter(e => !CONTAINER_PREFIXES.has(e.prefix)));
  const blocked: BlockedRow[] = fw.rows.map(({ e, n }) => ({
    reason: code(prefixWord(e.prefix)),
    layer: 'firewall',
    tries: n,
    what: destination(`${e.dst}:${e.dport}`, e.dport, e.proto, e.uid ? `uid ${e.uid}` : '')
  }));
  return { ...emptySection(), blocked };
}
