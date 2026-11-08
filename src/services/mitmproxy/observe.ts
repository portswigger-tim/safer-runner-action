/** Post step: what the proxy saw, from its flow log, for its part of the summary. */

import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import { FLOW_LOG, POLICY_FILE } from '../../constants';
import { parseFlowLogWithOffsets, type FlowRecord } from '../../flowlog';
import { parseAllowedDomains } from '../../policy';
import { suggestHttpFilter } from '../../report/suggest';
import { type SelfTestWindow, withoutSelfTests } from '../../setup/selftest';
import { summarizeFlows, type AllowedRequest } from './flows';
import { summarizeHttpFilter, type HttpFilterSuggestion } from './http-filter';
import { actionRoot } from './index';
import type { ProxyObserved } from './report';

/** GitHub platform endpoints the built-in list allowed on filtered hosts (policy.json, 0644). */
function readPlatformAutoAllowed(): number | undefined {
  try {
    const n = JSON.parse(fs.readFileSync(POLICY_FILE, 'utf8'))?.http_filter?.platform_auto_allowed;
    return typeof n === 'number' ? n : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The suggested http-filter (proxy/suggest.py, from the action checkout). A failure costs only
 * the suggestion: the rest of the report still renders.
 */
function suggestion(requests: AllowedRequest[]): HttpFilterSuggestion | undefined {
  try {
    return suggestHttpFilter(requests, path.join(actionRoot(), 'proxy'));
  } catch (error) {
    core.warning(`No suggested http-filter: ${error}`);
    return undefined;
  }
}

/**
 * The flow log less the setup self-tests' records, and the proxy's observations from it (all but
 * the DNS refusals, which are the resolver's). The records also feed the container part.
 */
export function observeProxy(selfTestWindow: SelfTestWindow | undefined): {
  records: FlowRecord[];
  observed: Omit<ProxyObserved, 'dnsRefused'>;
} {
  const flows = fs.existsSync(FLOW_LOG)
    ? parseFlowLogWithOffsets(fs.readFileSync(FLOW_LOG, 'utf8'))
    : { records: [], offsets: [] };
  const records = withoutSelfTests(flows.records, flows.offsets, selfTestWindow);
  return {
    records,
    observed: {
      hosts: summarizeFlows(records),
      httpFilter: summarizeHttpFilter(records, suggestion),
      // allow = GitHub list + these, so allowed traffic to anything else is GitHub's own
      userDomains: [
        ...parseAllowedDomains(core.getInput('allowed-domains')),
        ...parseAllowedDomains(core.getInput('passthrough-domains'))
      ],
      platformEndpoints: readPlatformAutoAllowed()
    }
  };
}
