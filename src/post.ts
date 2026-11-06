import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import { DNS_LOG, FIREWALL_LOG, FLOW_LOG, SELFTEST_FILE, SUDO_LOG, TEARDOWN_BIN } from './constants';
import { SETUP_MARKER } from './egress';
import { parseFlowLogWithOffsets } from './flowlog';
import { readRefusedNames } from './parsers/dns-parser';
import {
  blockedName,
  buildReport,
  parseFirewallLog,
  summarizeContainers,
  summarizeFlows,
  summarizeHttpFilter
} from './report';
import { containerAddresses } from './docker';
import { type SelfTestWindow, withoutSelfTests } from './selftest';
import { readSudoUsage } from './sudo';
import { SystemValidator } from './validation';
import { parseAllowedDomains, type Mode } from './policy';
import { effectiveFailOnTampering } from './inputs';

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
}

function readSetupMarker(): SetupMarker | null {
  try {
    return JSON.parse(fs.readFileSync(SETUP_MARKER, 'utf8')) as SetupMarker;
  } catch {
    return null;
  }
}

/**
 * Post step: destroy the CA private key, then report. The proxy and firewall stay up: the
 * runner's own "Complete job" traffic still goes through them, and the VM is destroyed after.
 */
async function run(): Promise<void> {
  const marker = readSetupMarker();
  const mode = marker?.mode;
  if (!marker || !mode) {
    core.warning('safer-runner setup did not complete - no report');
    return;
  }

  // -n: never prompt; the helper is allowlisted even with disable-sudo
  const rc = await exec.exec('sudo', ['-n', TEARDOWN_BIN], { ignoreReturnCode: true });
  if (rc === 0) core.info('🔑 Ephemeral CA private key destroyed');
  else core.warning(`Could not run ${TEARDOWN_BIN} (exit ${rc}); the CA key dies with the VM`);

  // integrity first, outside the report: a report failure must never skip fail-on-tampering
  const validator = new SystemValidator();
  let intact = false;
  try {
    intact = await validator.verifyAgainstBaseline();
  } catch (error) {
    core.warning(`Integrity check failed: ${error}`);
  }

  try {
    await new Promise(r => setTimeout(r, 1000)); // let the last flow / syslog lines land
    const flows = fs.existsSync(FLOW_LOG)
      ? parseFlowLogWithOffsets(fs.readFileSync(FLOW_LOG, 'utf8'))
      : { records: [], offsets: [] };
    const records = withoutSelfTests(flows.records, flows.offsets, marker.selfTestWindow);
    const hosts = summarizeFlows(records);
    const httpFilter = summarizeHttpFilter(records);
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
      core.info(`${b.verdict.padEnd(11)} http-filter ${b.host} ${b.method} ${b.path} tries=${b.tries} ${b.reason}`);
    }

    const integrity = await validator.generateValidationDetails();
    const sudo = readSudoUsage(SUDO_LOG);
    for (const c of sudo.ran) core.info(`sudo (workflow) ${c.command} ${c.args}`);
    for (const c of sudo.refused) core.info(`sudo REFUSED ${c.command} ${c.args}`);

    const md = buildReport({
      mode,
      sudoRetained: marker.sudoRetained === true,
      dockerRetained: marker.dockerRetained === true,
      docker: marker.docker,
      sudo,
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
      integrity,
      containers,
      httpFilter
      // TODO(http-filter integration): pass platformEndpoints from the count the engine writes to
      // policy.json (POLICY_FILE) once that field exists.
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
