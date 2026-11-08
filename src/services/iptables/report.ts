/**
 * The firewall's part of the job summary: connections that went around the proxy (only TCP 80/443
 * is proxied), from the host filter chain's LOG lines. The container chain's lines are reported
 * with their container (services/docker/containers.ts).
 */

import { CONTAINER_PREFIXES, firewallSummary, type FirewallEvent, type FirewallSummary } from './log';
import { capped, code, table } from '../../report/markdown';
import type { ReportContext, Section } from '../../report/section';

export interface FirewallObserved {
  events: FirewallEvent[];
}

const PORT_NAMES: Record<string, string> = {
  '22': 'SSH',
  '25': 'SMTP',
  '53': 'DNS',
  '123': 'NTP',
  '443': 'HTTPS (not proxied)',
  '80': 'HTTP (not proxied)',
  '853': 'DNS-over-TLS',
  '3128': 'HTTP proxy',
  '8080': 'HTTP-alt',
  '9418': 'git'
};

function destinationText(e: FirewallEvent): string {
  const likely = PORT_NAMES[e.dport];
  return `${likely ? `${likely} to ` : ''}${code(`${e.dst}:${e.dport}`)}`;
}

function score(fw: FirewallSummary): string[][] {
  if (!fw.rows.length) return [];
  const parts = [];
  if (fw.rejected) parts.push(`${fw.rejected} rejected`);
  if (fw.logged) parts.push(`${fw.logged} allowed, not proxied`);
  const one = fw.rows.length === 1 ? ` (${destinationText(fw.rows[0].e)})` : '';
  return [['🧱 **Outside the proxy**', parts.join(' · ') + one]];
}

function diagnostics(fw: FirewallSummary): Section['diagnostics'] {
  if (!fw.rows.length) return [{ summary: 'nothing bypassed the proxy', body: '' }];
  const p = [];
  if (fw.rejected) p.push(`${fw.rejected} non-proxy ${fw.rejected === 1 ? 'destination' : 'destinations'} rejected`);
  if (fw.logged) p.push(`${fw.logged} allowed outside the proxy`);
  const { shown, note } = capped(fw.rows);
  let body =
    '**Outside the proxy** <sub>(only TCP 80/443 is proxied; new connections only; logging rate-limited to 60/min)</sub>\n\n';
  body += table(
    ['Destination', 'Proto', 'Likely', 'UID', 'Packets', 'Result'],
    [':--', ':--', ':--', '--:', '--:', ':--'],
    shown.map(({ e, n }) => [
      code(`${e.dst}:${e.dport}`),
      e.proto,
      PORT_NAMES[e.dport] ?? '',
      e.uid,
      String(n),
      e.prefix === 'SaferRunner-Drop' ? '❌ rejected' : '⚠️ allowed (not proxied)'
    ])
  );
  body += note + '\n\n';
  return [{ summary: p.join(' · '), body }];
}

export function report(o: FirewallObserved, _ctx: ReportContext): Section {
  // container firewall events are reported in the container section, with their source
  const fw = firewallSummary(o.events.filter(e => !CONTAINER_PREFIXES.has(e.prefix)));
  return {
    chips: [],
    alerts: [],
    score: score(fw),
    blocking: fw.rows.length > 0,
    body: '',
    diagnostics: diagnostics(fw),
    jobLog: [],
    advisory: ''
  };
}
