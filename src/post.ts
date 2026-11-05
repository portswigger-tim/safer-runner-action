import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import { DNS_LOG, FIREWALL_LOG, FLOW_LOG, SELFTEST_FILE, SUDO_LOG, TEARDOWN_BIN } from './constants';
import { SETUP_MARKER } from './egress';
import { parseFlowLogWithOffsets } from './flowlog';
import { parseAllowedDomains } from './config/dns-config-builder';
import { parseDnsLogs } from './parsers/dns-parser';
import { buildReport, parseDnsRebind, parseFirewallLog, summarizeFlows } from './report';
import { type SelfTestWindow, withoutSelfTests } from './selftest';
import { readSudoUsage } from './sudo';
import { SystemValidator } from './validation';
import type { Mode } from './policy';

interface SetupMarker {
  mode: Mode;
  sudoRetained?: boolean;
  dockerRetained?: boolean;
  /** flow-log byte range the setup self-tests wrote */
  selfTestWindow?: SelfTestWindow;
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
    const hosts = summarizeFlows(withoutSelfTests(flows.records, flows.offsets, marker.selfTestWindow));
    const firewall = fs.existsSync(FIREWALL_LOG) ? parseFirewallLog(fs.readFileSync(FIREWALL_LOG, 'utf8')) : [];
    const dns = await parseDnsLogs(DNS_LOG);
    const dnsRefused = Array.from(new Set(dns.filter(d => /NXDOMAIN|blocked/i.test(d.status)).map(d => d.domain)));
    const dnsRebind = fs.existsSync(DNS_LOG) ? parseDnsRebind(fs.readFileSync(DNS_LOG, 'utf8')) : [];
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
      dnsRebind,
      // allow = GitHub list + these, so allowed traffic to anything else is GitHub's own
      userDomains: [
        ...parseAllowedDomains(core.getInput('allowed-domains')),
        ...parseAllowedDomains(core.getInput('passthrough-domains'))
      ],
      selfTests,
      integrity
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
