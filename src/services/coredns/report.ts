/** The resolver's part of the job summary: names it blocked (enforce) or would block (analyze). */

import { blockedName } from '../mitmproxy/flows';
import { code } from '../../report/markdown';
import { emptySection, type ReportContext, type Section } from '../../report/section';

export interface DnsObserved {
  /** blocked names, the setup self-test excluded */
  refused: string[];
}

/** `shown`: names the proxy part already lists with their blocked connection. */
export function report(o: DnsObserved, ctx: ReportContext, shown: readonly string[] = []): Section {
  const shownAbove = new Set(shown.map(n => n.toLowerCase()));
  // the label each line of dns.log carries (src/services/coredns/config.ts)
  const reason = code(ctx.enforce ? 'BLOCK' : 'WOULD_BLOCK');
  return {
    ...emptySection(),
    blocked: o.refused
      .filter(d => !shownAbove.has(d.toLowerCase()))
      .map(n => ({ reason, layer: 'dns', what: code(blockedName(n)) }))
  };
}
