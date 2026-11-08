/** Post step: the sudo policy against the workflow's own sudo use, for sudo's part of the summary. */

import * as core from '@actions/core';
import * as path from 'path';
import type { Mode } from '../../policy';
import { suggestSudoConfig } from '../../report/suggest';
import { actionRoot } from '../mitmproxy/index';
import { evaluateSudo, parseSudoLine, runnerWritableDirs, sudoRuleWarning, type SudoRule } from './config';
import type { SudoCommand } from './log';
import type { SudoPolicyReport } from './report';

/** What the setup marker recorded about sudo (root-owned, not re-read from the inputs). */
export interface SudoMarker {
  sudoRetained?: boolean;
  /** sudo-config lines setup used (absent: none) */
  sudoConfig?: string[];
  /** analyze with disable-sudo: false (the policy keeps sudo) */
  sudoKept?: boolean;
}

/**
 * The sudo policy setup recorded and, in analyze, what it would block in enforce and the
 * suggested sudo-config.
 */
export function observeSudoPolicy(mode: Mode, marker: SudoMarker, ran: SudoCommand[]): SudoPolicyReport {
  let rules: SudoRule[] = [];
  try {
    rules = (marker.sudoConfig ?? []).map(parseSudoLine);
  } catch (error) {
    core.warning(`Unreadable sudo-config in the setup marker: ${error}`);
  }
  const kept = marker.sudoRetained === true || marker.sudoKept === true;
  // the lines as recorded: if they do not parse back, the report still counts them (ADVISORY),
  // and analyze evaluates against no rules (everything would be blocked)
  const policy: SudoPolicyReport = { rules: [...(marker.sudoConfig ?? [])], kept, wouldBlock: [] };
  if (mode !== 'analyze') return policy;
  policy.wouldBlock = evaluateSudo(rules, kept, ran).wouldBlock;
  if (ran.length) {
    try {
      const suggestion = suggestSudoConfig(ran, path.join(actionRoot(), 'proxy'));
      const writable = runnerWritableDirs();
      policy.suggestion = suggestion;
      policy.flagged = Object.fromEntries(
        suggestion.rules.flatMap(line => {
          const why = sudoRuleWarning(parseSudoLine(line), writable);
          return why ? [[line, why]] : [];
        })
      );
    } catch (error) {
      core.warning(`No suggested sudo-config: ${error}`);
    }
  }
  return policy;
}
