import * as core from '@actions/core';
import * as fs from 'fs';
import { SELFTEST_FILE, SUDO_LOG } from './constants';
import { SETUP_MARKER } from './setup/run';
import { compose, reportSections, suggestedForLog } from './report/compose';
import { jobLog as proxyJobLog } from './services/mitmproxy/report';
import { jobLog as sudoJobLog } from './services/sudo/report';
import { jobLog as dockerJobLog } from './services/docker/report';
import { observeProxy } from './services/mitmproxy/observe';
import { observeFirewall } from './services/iptables/observe';
import { observeDns } from './services/coredns/observe';
import { observeSudoPolicy, type SudoMarker } from './services/sudo/observe';
import { SETUP_FINAL_SUDO, readSudoUsage } from './services/sudo';
import { observeContainers, observeDockerPolicy, type DockerMarker } from './services/docker/observe';
import { type SelfTestWindow } from './setup/selftest';
import { checkIntegrity, type IntegrityResult } from './integrity/check';
import { realHost } from './system/host';
import { effectiveFailOnTampering } from './config/inputs';

interface SetupMarker extends SudoMarker, DockerMarker {
  dockerRetained?: boolean;
  /** the job's own allowed-domains and passthrough-domains entries, as setup applied them */
  allowedDomains?: string[];
  passthroughDomains?: string[];
  /** resolved fail-on-tampering (mode-aware); kept in the root-owned marker, not re-read from inputs */
  failOnTampering?: boolean;
  /** flow-log byte range the setup self-tests wrote */
  selfTestWindow?: SelfTestWindow;
  /** the name the DNS self-test looked up (refused by design; not the job's traffic) */
  dnsSelfTestName?: string;
}

const log = (lines: string[]) => lines.forEach(l => core.info(l));

/** A file's size in bytes, read without stat (undefined when it cannot be read). */
function fileSize(file: string): number | undefined {
  try {
    return fs.readFileSync(file).length;
  } catch {
    return undefined;
  }
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
  // let the job's last flow, syslog and sudo lines land (sudo-rs reaches the sudo log through
  // rsyslog), then take the sudo log as this step found it: anything after is this step's own
  await new Promise(r => setTimeout(r, 1000));
  const sudoLogBytes = fileSize(SUDO_LOG);
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
    // Each service's observations (its own log, and its policy where it has one). Its full lists
    // go to the job log as soon as it has them, so a later failure never loses them (names and
    // sudo arguments redacted like the summary: the job log is just as public).
    const proxy = observeProxy(marker.selfTestWindow, {
      allowed: marker.allowedDomains,
      passthrough: marker.passthroughDomains
    });
    log(proxyJobLog(proxy.observed));
    const firewall = observeFirewall();
    const containers = await observeContainers(proxy.records, firewall);
    const dnsRefused = observeDns(marker.dnsSelfTestName);
    const selfTests = readSelfTests();
    const restricted = mode === 'enforce' && marker.sudoRetained !== true;
    const sudo = readSudoUsage(SUDO_LOG, {
      postStartBytes: sudoLogBytes,
      setupFinal: restricted ? SETUP_FINAL_SUDO.restricted : SETUP_FINAL_SUDO.unrestricted,
      markerAt: marker.at ? new Date(marker.at) : undefined
    });
    const sudoPolicy = observeSudoPolicy(mode, marker, sudo?.ran ?? []);
    log(sudoJobLog({ usage: sudo, policy: sudoPolicy }));
    const dockerPolicy = await observeDockerPolicy(marker);
    log(dockerJobLog(dockerPolicy));

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
      actionRepository: process.env.GITHUB_ACTION_REPOSITORY,
      actionRef: process.env.GITHUB_ACTION_REF,
      ...proxy.observed,
      firewall,
      dnsRefused,
      selfTests,
      integrity: integrity?.details,
      containers
    });
    const block = suggestedForLog(sections);
    if (block) {
      core.startGroup('Suggested enforce configuration');
      log(block.split('\n'));
      core.endGroup();
    }
    await core.summary.addRaw(compose(sections)).write();
  } catch (error) {
    core.warning(`Failed to generate the safer-runner report: ${error}`);
  }

  if (!intact && effectiveFailOnTampering(marker.failOnTampering, core.getInput('fail-on-tampering'), mode)) {
    core.setFailed('🚨 Security configuration was tampered with (or could not be verified) during the job');
  }
}

run();
