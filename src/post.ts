import * as core from '@actions/core';
import * as fs from 'fs';
import * as path from 'path';
import { DNS_LOG, FIREWALL_LOG, FLOW_LOG, POLICY_FILE, SELFTEST_FILE, SUDO_LOG } from './constants';
import { SETUP_MARKER } from './setup/run';
import { parseFlowLogWithOffsets } from './flowlog';
import {
  PATH_HIDDEN,
  blockedName,
  buildReport,
  parseFirewallLog,
  readRefusedNames,
  suggestHttpFilter,
  suggestSudoConfig,
  summarizeContainers,
  summarizeFlows,
  summarizeHttpFilter,
  type AllowedRequest,
  type HttpFilterSuggestion,
  type SudoCommand,
  type SudoPolicyReport
} from './report';
import { containerAddresses } from './services/docker';
import { actionRoot } from './services/mitmproxy';
import { type SelfTestWindow, withoutSelfTests } from './setup/selftest';
import {
  evaluateSudo,
  parseSudoLine,
  readSudoUsage,
  runnerWritableDirs,
  sudoRuleWarning,
  type SudoRule
} from './services/sudo';
import { checkIntegrity, type IntegrityResult } from './integrity/check';
import { realHost } from './system/host';
import { parseAllowedDomains, type Mode } from './policy';
import { effectiveFailOnTampering } from './config/inputs';

interface SetupMarker {
  mode: Mode;
  sudoRetained?: boolean;
  dockerRetained?: boolean;
  /** the docker input and the verified access (G4) */
  docker?: { requested: string; access: 'retained' | 'group-removed' | 'not-running' };
  /** resolved fail-on-tampering (mode-aware); kept in the root-owned marker, not re-read from inputs */
  failOnTampering?: boolean;
  /** flow-log byte range the setup self-tests wrote */
  selfTestWindow?: SelfTestWindow;
  /** the name the DNS self-test looked up (refused by design; not the job's traffic) */
  dnsSelfTestName?: string;
  /** sudo-config lines setup used (absent: none) */
  sudoConfig?: string[];
  /** analyze with disable-sudo: false (the policy keeps sudo) */
  sudoKept?: boolean;
}

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
 * The sudo policy setup recorded (in the root-owned marker, not re-read from the inputs) and,
 * in analyze, what it would block in enforce and the suggested sudo-config.
 */
function sudoPolicy(mode: Mode, marker: SetupMarker, ran: SudoCommand[]): SudoPolicyReport {
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

function readSetupMarker(): SetupMarker | null {
  try {
    return JSON.parse(fs.readFileSync(SETUP_MARKER, 'utf8')) as SetupMarker;
  } catch {
    return null;
  }
}

/**
 * Post step: integrity check, then report. The proxy and firewall stay up: the runner's own
 * "Complete job" traffic still goes through them, and the VM is destroyed after (the CA key, on
 * tmpfs, with it).
 */
async function run(): Promise<void> {
  const marker = readSetupMarker();
  const mode = marker?.mode;
  if (!marker || !mode) {
    core.warning('safer-runner setup did not complete - no report');
    return;
  }

  // integrity first, outside the report: a report failure must never skip fail-on-tampering.
  // One comparison: the verdict here and the summary's details come from the same reads.
  let integrity: IntegrityResult | undefined;
  try {
    integrity = await checkIntegrity(realHost);
  } catch (error) {
    core.warning(`Integrity check failed: ${error}`);
  }
  const intact = integrity?.intact === true;

  try {
    await new Promise(r => setTimeout(r, 1000)); // let the last flow / syslog lines land
    const flows = fs.existsSync(FLOW_LOG)
      ? parseFlowLogWithOffsets(fs.readFileSync(FLOW_LOG, 'utf8'))
      : { records: [], offsets: [] };
    const records = withoutSelfTests(flows.records, flows.offsets, marker.selfTestWindow);
    const hosts = summarizeFlows(records);
    const httpFilter = summarizeHttpFilter(records, suggestion);
    const firewall = fs.existsSync(FIREWALL_LOG) ? parseFirewallLog(fs.readFileSync(FIREWALL_LOG, 'utf8')) : [];
    const containers = summarizeContainers(records, firewall, await containerAddresses());
    const dnsRefused = readRefusedNames(DNS_LOG).filter(n => n !== marker.dnsSelfTestName);
    let selfTests = [];
    try {
      selfTests = JSON.parse(fs.readFileSync(SELFTEST_FILE, 'utf8'));
    } catch {
      selfTests = [];
    }

    // Full lists in the job log, so nothing is ever silently dropped from the summary (names
    // redacted like the summary: the job log is just as public).
    for (const h of hosts) {
      core.info(
        `${h.verdict.padEnd(11)} ${blockedName(h.name)} conns=${h.connections} reqs=${h.requests} tries=${h.tries} ${h.reasons.join(',')}`
      );
    }
    for (const b of httpFilter.blocks) {
      core.info(
        `${b.verdict.padEnd(11)} http-filter ${b.host} ${b.method} ${PATH_HIDDEN} tries=${b.tries} ${b.reason}`
      );
    }

    const sudo = readSudoUsage(SUDO_LOG);
    for (const c of sudo.ran) core.info(`sudo (workflow) ${c.command} ${c.args}`);
    for (const c of sudo.refused) core.info(`sudo REFUSED ${c.command} ${c.args}`);
    const sudoPolicyReport = sudoPolicy(mode, marker, sudo.ran);
    for (const c of sudoPolicyReport.wouldBlock) core.info(`sudo WOULD_BLOCK ${c.command} ${c.args}`);

    const md = buildReport({
      mode,
      sudoRetained: marker.sudoRetained === true,
      dockerRetained: marker.dockerRetained === true,
      docker: marker.docker,
      sudo,
      sudoPolicy: sudoPolicyReport,
      job: process.env.GITHUB_JOB || 'unknown',
      actionRef: process.env.GITHUB_ACTION_REF,
      hosts,
      firewall,
      dnsRefused,
      // allow = GitHub list + these, so allowed traffic to anything else is GitHub's own
      userDomains: [
        ...parseAllowedDomains(core.getInput('allowed-domains')),
        ...parseAllowedDomains(core.getInput('passthrough-domains'))
      ],
      selfTests,
      integrity: integrity?.details,
      containers,
      httpFilter,
      platformEndpoints: readPlatformAutoAllowed()
    });
    await core.summary.addRaw(md).write();
  } catch (error) {
    core.warning(`Failed to generate the safer-runner report: ${error}`);
  }

  if (!intact && effectiveFailOnTampering(marker.failOnTampering, core.getInput('fail-on-tampering'), mode)) {
    core.setFailed('🚨 Security configuration was tampered with (or could not be verified) during the job');
  }
}

run();
