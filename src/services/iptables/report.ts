/**
 * The firewall's part of the job summary: connections that went around the proxy (only TCP 80/443
 * is proxied), from the host filter chain's LOG lines. The container chain's lines are reported
 * with their container (services/docker/containers.ts).
 */

import { CONTAINER_PREFIXES, firewallSummary, type FirewallEvent, type FirewallSummary } from './log';
import { capped, code, plural, table } from '../../report/markdown';
import {
  VERDICT_ICON,
  emptySection,
  refusedVerdict,
  type ReportContext,
  type RunnerSystem,
  type ScoreRow,
  type Section
} from '../../report/section';

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

function score(fw: FirewallSummary, ctx: ReportContext): ScoreRow[] {
  if (!fw.rows.length) return [];
  const one = fw.rows.length === 1 ? ` (${destinationText(fw.rows[0].e)})` : '';
  return [
    {
      verdict: refusedVerdict(ctx),
      area: 'Network',
      text: `${plural(fw.rows.length, 'connection')} outside the proxy ${ctx.enforce ? 'rejected' : 'would be rejected'}${one}`
    }
  ];
}

function runnerSystem(fw: FirewallSummary, ctx: ReportContext): RunnerSystem[] {
  if (!fw.rows.length) return [{ summary: 'nothing outside the proxy', body: '' }];
  const { shown, note } = capped(fw.rows);
  let body =
    '**Outside the proxy** <sub>(only TCP 80/443 is proxied; new connections only; logging rate-limited to 60/min)</sub>\n\n';
  body += table(
    ['', 'Destination', 'Proto', 'Likely', 'UID', 'Packets'],
    [':-:', ':--', ':--', ':--', '--:', '--:'],
    shown.map(({ e, n }) => [
      VERDICT_ICON[e.prefix === 'SaferRunner-Drop' ? 'blocked' : refusedVerdict(ctx)],
      code(`${e.dst}:${e.dport}`),
      e.proto,
      PORT_NAMES[e.dport] ?? '',
      e.uid,
      String(n)
    ])
  );
  body += note + '\n\n';
  return [{ summary: `${plural(fw.rows.length, 'connection')} outside the proxy`, body }];
}

export function report(o: FirewallObserved, ctx: ReportContext): Section {
  // container firewall events are reported in the container part, with their source
  const fw = firewallSummary(o.events.filter(e => !CONTAINER_PREFIXES.has(e.prefix)));
  return { ...emptySection(), score: score(fw, ctx), runnerSystem: runnerSystem(fw, ctx) };
}
