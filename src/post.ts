import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import { DNS_LOG, FIREWALL_LOG, FLOW_LOG, POLICY_FILE, SELFTEST_FILE, SUDO_LOG, TEARDOWN_BIN } from './constants';
import { SETUP_MARKER } from './egress';
import { parseFlowLogWithOffsets } from './flowlog';
import { readRefusedNames } from './parsers/dns-parser';
import { buildReport, parseFirewallLog, summarizeContainers, summarizeFlows } from './report';
import { containerAddresses } from './docker';
import { type SelfTestWindow, withoutSelfTests } from './selftest';
import { readSudoUsage } from './sudo';
import { SystemValidator } from './validation';
import { parseAllowedDomains, type Mode } from './policy';

interface SetupMarker {
  mode: Mode;
  sudoRetained?: boolean;
  dockerRetained?: boolean;
  /** flow-log byte range the setup self-tests wrote */
  selfTestWindow?: SelfTestWindow;
  /** the name the DNS self-test looked up (refused by design; not the job's traffic) */
  dnsSelfTestName?: string;
}

/** allow + passthrough from the root-owned policy the proxy and the resolver were built from. */
function readPolicyPatterns(): string[] | undefined {
  try {
    const p = JSON.parse(fs.readFileSync(POLICY_FILE, 'utf8')) as { allow?: string[]; passthrough?: string[] };
    return [...(p.allow ?? []), ...(p.passthrough ?? [])];
  } catch {
    return undefined;
  }
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

  try {
    await new Promise(r => setTimeout(r, 1000)); // let the last flow / syslog lines land
    const flows = fs.existsSync(FLOW_LOG)
      ? parseFlowLogWithOffsets(fs.readFileSync(FLOW_LOG, 'utf8'))
      : { records: [], offsets: [] };
    const records = withoutSelfTests(flows.records, flows.offsets, marker.selfTestWindow);
    const hosts = summarizeFlows(records);
    const firewall = fs.existsSync(FIREWALL_LOG) ? parseFirewallLog(fs.readFileSync(FIREWALL_LOG, 'utf8')) : [];
    const containers = summarizeContainers(records, firewall, await containerAddresses());
    const dnsRefused = readRefusedNames(DNS_LOG).filter(n => n !== marker.dnsSelfTestName);
    let selfTests = [];
    try {
      selfTests = JSON.parse(fs.readFileSync(SELFTEST_FILE, 'utf8'));
    } catch {
      selfTests = [];
    }

    // Full lists in the job log, so nothing is ever silently dropped from the summary.
    for (const h of hosts) {
      core.info(
        `${h.verdict.padEnd(11)} ${h.name} conns=${h.connections} reqs=${h.requests} tries=${h.tries} ${h.reasons.join(',')}`
      );
    }

    const validator = new SystemValidator();
    const intact = await validator.verifyAgainstBaseline();
    const integrity = await validator.generateValidationDetails();
    const sudo = readSudoUsage(SUDO_LOG);
    for (const c of sudo.ran) core.info(`sudo (workflow) ${c.command} ${c.args}`);
    for (const c of sudo.refused) core.info(`sudo REFUSED ${c.command} ${c.args}`);

    const md = buildReport({
      mode,
      sudoRetained: marker.sudoRetained === true,
      dockerRetained: marker.dockerRetained === true,
      sudo,
      job: process.env.GITHUB_JOB || 'unknown',
      hosts,
      firewall,
      dnsRefused,
      allowPatterns: readPolicyPatterns(),
      // allow = GitHub list + these, so allowed traffic to anything else is GitHub's own
      userDomains: [
        ...parseAllowedDomains(core.getInput('allowed-domains')),
        ...parseAllowedDomains(core.getInput('passthrough-domains'))
      ],
      selfTests,
      integrity,
      containers
    });
    await core.summary.addRaw(md).write();

    if (!intact && core.getInput('fail-on-tampering') === 'true') {
      core.setFailed('🚨 Security configuration was tampered with during the job');
    }
  } catch (error) {
    core.warning(`Failed to generate the safer-runner report: ${error}`);
  }
}

run();
