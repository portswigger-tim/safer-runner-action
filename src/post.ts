import * as core from '@actions/core';
import * as fs from 'fs';
import { SELFTEST_FILE, SUDO_LOG } from './constants';
import { SETUP_MARKER } from './setup/run';
import { compose, jobLog, reportSections } from './report/compose';
import { observeProxy } from './services/mitmproxy/observe';
import { observeFirewall } from './services/iptables/observe';
import { observeDns } from './services/coredns/observe';
import { observeSudoPolicy, type SudoMarker } from './services/sudo/observe';
import { readSudoUsage } from './services/sudo';
import { observeContainers, observeDockerPolicy, type DockerMarker } from './services/docker/observe';
import { type SelfTestWindow } from './setup/selftest';
import { checkIntegrity, type IntegrityResult } from './integrity/check';
import { realHost } from './system/host';
import { effectiveFailOnTampering } from './config/inputs';

interface SetupMarker extends SudoMarker, DockerMarker {
  dockerRetained?: boolean;
  /** resolved fail-on-tampering (mode-aware); kept in the root-owned marker, not re-read from inputs */
  failOnTampering?: boolean;
  /** flow-log byte range the setup self-tests wrote */
  selfTestWindow?: SelfTestWindow;
  /** the name the DNS self-test looked up (refused by design; not the job's traffic) */
  dnsSelfTestName?: string;
}

function readSelfTests(): { name: string; ok: boolean; detail: string }[] {
  try {
    return JSON.parse(fs.readFileSync(SELFTEST_FILE, 'utf8'));
  } catch {
    return [];
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
    // each service's observations (its own log, and its policy where it has one)
    const proxy = observeProxy(marker.selfTestWindow);
    const firewall = observeFirewall();
    const containers = await observeContainers(proxy.records, firewall);
    const dnsRefused = observeDns(marker.dnsSelfTestName);
    const selfTests = readSelfTests();
    const sudo = readSudoUsage(SUDO_LOG);
    const sudoPolicy = observeSudoPolicy(mode, marker, sudo.ran);
    const dockerPolicy = await observeDockerPolicy(marker);

    // each service's part, then the summary from the parts
    const sections = reportSections({
      mode,
      sudoRetained: marker.sudoRetained === true,
      dockerRetained: marker.dockerRetained === true,
      docker: marker.docker,
      dockerPolicy,
      sudo,
      sudoPolicy,
      job: process.env.GITHUB_JOB || 'unknown',
      actionRef: process.env.GITHUB_ACTION_REF,
      ...proxy.observed,
      firewall,
      dnsRefused,
      selfTests,
      integrity: integrity?.details,
      containers
    });
    // Full lists in the job log, so nothing is ever silently dropped from the summary (names
    // and sudo arguments redacted like the summary: the job log is just as public).
    for (const line of jobLog(sections)) core.info(line);
    await core.summary.addRaw(compose(sections)).write();
  } catch (error) {
    core.warning(`Failed to generate the safer-runner report: ${error}`);
  }

  if (!intact && effectiveFailOnTampering(marker.failOnTampering, core.getInput('fail-on-tampering'), mode)) {
    core.setFailed('🚨 Security configuration was tampered with (or could not be verified) during the job');
  }
}

run();
