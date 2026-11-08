/** The resolver's part of the job summary: names it refused (enforce) or would refuse (analyze). */

import { blockedName } from '../mitmproxy/flows';
import { capped, code, plural } from '../../report/markdown';
import type { ReportContext, Section } from '../../report/section';

export interface DnsObserved {
  /** refused names, the setup self-test excluded */
  refused: string[];
}

/** `shown`: names the proxy part already lists with their blocked connection. */
export function report(o: DnsObserved, ctx: ReportContext, shown: readonly string[] = []): Section {
  const { enforce } = ctx;
  const diagnostics: Section['diagnostics'] = [];
  if (o.refused.length) {
    const shownAbove = new Set(shown);
    const rest = o.refused.filter(d => !shownAbove.has(d.toLowerCase()));
    const { shown: listed, note } = capped(rest);
    let body = `**DNS ${enforce ? 'refused' : 'would refuse'}** (${o.refused.length}): `;
    body += rest.length
      ? listed.map(n => code(blockedName(n))).join(', ') + note
      : 'all of them are listed with their blocked connection above';
    body += '\n\n';
    diagnostics.push({
      summary: plural(o.refused.length, enforce ? 'DNS refusal' : 'DNS lookup enforce would refuse'),
      body
    });
  }
  return { chips: [], alerts: [], score: [], blocking: false, body: '', diagnostics, jobLog: [], advisory: '' };
}
