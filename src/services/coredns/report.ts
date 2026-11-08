/** The resolver's part of the job summary: names it refused (enforce) or would refuse (analyze). */

import { blockedName } from '../mitmproxy/flows';
import { capped, code, plural, table } from '../../report/markdown';
import { VERDICT_ICON, emptySection, refusedVerdict, type ReportContext, type Section } from '../../report/section';

export interface DnsObserved {
  /** refused names, the setup self-test excluded */
  refused: string[];
}

/** `shown`: names the proxy part already lists with their blocked connection. */
export function report(o: DnsObserved, ctx: ReportContext, shown: readonly string[] = []): Section {
  if (!o.refused.length) return emptySection();
  const shownAbove = new Set(shown);
  const rest = o.refused.filter(d => !shownAbove.has(d.toLowerCase()));
  const { shown: listed, note } = capped(rest);
  const icon = VERDICT_ICON[refusedVerdict(ctx)];
  const body = rest.length
    ? table(
        ['', `DNS ${ctx.enforce ? 'refused' : 'would refuse'}`],
        [':-:', ':--'],
        listed.map(n => [icon, code(blockedName(n))])
      ) +
      note +
      '\n\n'
    : `**DNS**: every name it ${ctx.enforce ? 'refused' : 'would refuse'} is listed above with its blocked connection.\n\n`;
  return {
    ...emptySection(),
    runnerSystem: [
      { summary: `DNS ${plural(o.refused.length, 'name')} ${ctx.enforce ? 'refused' : 'enforce would refuse'}`, body }
    ]
  };
}
