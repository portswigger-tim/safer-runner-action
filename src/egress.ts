/**
 * v2 setup orchestration. Runs once per job - in the pre step (so the policy is enforced for
 * every later action's pre-hook too, review H2), or in the main step if pre did not run.
 *
 * Order (each step depends on the previous):
 *   allowlist (api.github.com/meta, before DNS changes) -> install (pinned CoreDNS + pinned
 *   mitmdump + conntrack, in parallel) -> users -> addon + policy + CA -> start proxy (waits for
 *   the addon's own self-test) -> trust (system store, GITHUB_ENV, Java) -> DNS (CoreDNS up
 *   first, then resolv.conf points at it) -> dockerd restart so it
 *   trusts the CA (F1) -> firewall (nat REDIRECT + filter, plus the container DNAT /
 *   DOCKER-USER rules when docker runs) -> kill pre-existing :443 and container flows ->
 *   live self-tests -> docker access -> sudo logging -> integrity baseline -> sudo
 *   restriction (last).
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import {
  FIREWALL_LOG,
  FLOW_LOG,
  DOCKER_DAEMON_JSON,
  LOG_PREFIX_ANALYZE,
  LOG_PREFIX_CDROP,
  LOG_PREFIX_CEGRESS,
  LOG_PREFIX_DROP,
  SELFTEST_FILE,
  SUDO_LOG
} from './constants';
import { flowLogSize } from './flowlog';
import {
  applyFirewall,
  detectEgressInterface,
  flushContainerConntrack,
  killPreexistingConnections,
  logFirewall
} from './firewall';
import type { Inputs } from './inputs';
import { buildPolicyConfig } from './policy';
import {
  allocateProxyPorts,
  createProxyUser,
  generateCa,
  installAddon,
  installMitmproxy,
  installTeardownHelper,
  startProxy,
  writePolicy
} from './proxy';
import { dnsProbeName, runSelfTests } from './selftest';
import {
  createLogDirectory,
  createRandomDNSUser,
  restartResolved,
  setupDNSConfig,
  setupIptablesLogging
} from './setup';
import { installCoreDns, startCoreDns, writeCorefile } from './dns';
import { resolveGitHubDomains } from './parsers/github-parser';
import {
  applyCustomSudoConfig,
  detectSudoFlavour,
  disableSudoForRunner,
  getSudoLoggingConfigFile,
  setupSudoLogging
} from './sudo';
import {
  disableDockerForRunner,
  isDockerActive,
  restartDockerForCaTrust,
  runningContainers,
  stopDockerService
} from './docker';
import { exportTrustEnv, installJavaTrust, installSystemTrust } from './trust';
import { CRITICAL_FILES, SystemValidator } from './validation';

/** Root-owned marker written when setup completed; checked by main (pre may not have run). */
export const SETUP_MARKER = '/etc/safer-runner/setup-complete';

/** Always allowlisted (GitHub core): CoreDNS is ready once it resolves this. */
const DNS_READY_NAME = 'github.com';

export function setupCompleted(): boolean {
  return fs.existsSync(SETUP_MARKER);
}

async function timed<T>(label: string, fn: () => Promise<T>): Promise<T> {
  const t0 = Date.now();
  try {
    return await core.group(label, fn);
  } finally {
    core.info(`⏱ ${label}: ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  }
}

/**
 * apt packages: conntrack only (flushes container flows that predate the container rules; not
 * on the image). Only refreshes the apt index if a plain install fails (saves ~10s).
 */
export async function installPackages(): Promise<void> {
  const opts = { ignoreReturnCode: true };
  const env = { ...process.env, DEBIAN_FRONTEND: 'noninteractive' } as { [key: string]: string };
  const install = ['apt-get', 'install', '-y', '-qq', '--no-install-recommends', 'conntrack'];
  if ((await exec.exec('sudo', ['-E', ...install], { ...opts, env })) === 0) return;
  await exec.exec('sudo', ['apt-get', 'update', '-qq']);
  await exec.exec('sudo', ['-E', ...install], { env });
}

/**
 * F3: with a job `container:`, JS actions run INSIDE that container (as root, no sudo, no
 * access to the host's iptables), so the action cannot apply anything to the runner VM.
 */
export function inJobContainer(exists: (p: string) => boolean = fs.existsSync): boolean {
  return exists('/.dockerenv') || exists('/run/.containerenv');
}

export const JOB_CONTAINER_MESSAGE =
  'safer-runner cannot protect a job that runs in a job `container:` - the action runs inside the ' +
  'container and cannot apply egress controls to the runner VM. Run the job on the runner and use ' +
  '`services:` and `docker run` steps instead (their egress is controlled).';

export async function runSetup(inputs: Inputs): Promise<void> {
  const { mode } = inputs;
  core.info(`🛡️ safer-runner v2: ${mode.toUpperCase()} mode (L7 egress proxy)`);

  if (inJobContainer()) {
    if (mode === 'enforce') throw new Error(JOB_CONTAINER_MESSAGE);
    core.warning(`${JOB_CONTAINER_MESSAGE} Analyze mode: nothing is monitored in this job.`, {
      title: 'safer-runner: job container not supported'
    });
    return;
  }
  if (inputs.containerTlsWarning) core.warning(inputs.containerTlsWarning);

  if (inputs.disableSudo && inputs.sudoConfig) {
    core.warning('Both disable-sudo and sudo-config are set. Ignoring sudo-config (disable-sudo takes precedence).');
  }
  if (inputs.stopDocker && inputs.disableDocker && !inputs.disableDockerDefaulted) {
    core.warning('Both stop-docker and disable-docker are set. stop-docker takes precedence.');
  }
  // enforce without sudo removal is advisory: any step can sudo the controls away (review H2)
  const sudoRetained = mode === 'enforce' && !inputs.disableSudo;
  const dockerRetained = !inputs.disableDocker && !inputs.stopDocker;
  if (sudoRetained) {
    core.warning(
      `enforce is ADVISORY in this job: sudo is retained (${inputs.sudoConfig ? 'sudo-config is set' : 'disable-sudo: false'}), ` +
        'so any step can use it to remove the egress controls. This is not an enforced boundary. ' +
        'Remove disable-sudo: false / sudo-config to make enforce a boundary.',
      { title: 'safer-runner: enforce (ADVISORY - sudo retained)' }
    );
  } else if (mode === 'enforce' && inputs.disableSudoDefaulted) {
    core.info('disable-sudo not set: enforce mode removes sudo by default (set disable-sudo: false to keep it)');
  }
  if (mode === 'enforce' && dockerRetained) {
    core.warning(
      'enforce with docker access: the docker group is root-equivalent, so a step can use docker to remove ' +
        'the egress controls. Set disable-docker: true or stop-docker: true unless the job needs docker.'
    );
  } else if (mode === 'enforce' && inputs.disableDockerDefaulted) {
    core.info(
      'disable-docker not set: enforce mode removes docker access by default (set disable-docker: false to keep it)'
    );
  }

  const sudoFlavour = await detectSudoFlavour();
  core.info(`sudo implementation: ${sudoFlavour}`);

  const ports = await allocateProxyPorts(inputs.proxyPort);
  core.info(`Proxy listeners: host 127.0.0.1:${ports.port}, containers 127.0.0.1:${ports.containerPort}`);

  // 1. Allowlist - fetched while normal DNS and direct egress still work
  const { domains: githubDomains, source } = await resolveGitHubDomains();
  core.info(`GitHub allowlist: ${githubDomains.length} domains (source: ${source})`);
  const { config: policy, warnings } = buildPolicyConfig({
    mode,
    githubDomains,
    allowedDomains: inputs.allowedDomains,
    passthroughDomains: inputs.passthroughDomains,
    blockRiskySubdomains: inputs.blockRiskySubdomains,
    containerTls: inputs.containerTls,
    containerPort: ports.containerPort
  });
  for (const w of warnings) core.warning(w);
  core.info(
    `Policy: ${policy.allow.length} allowed, passthrough [${policy.passthrough.join(', ')}], deny [${policy.deny.join(', ')}]`
  );

  const dnsServers = [inputs.primaryDnsServer, inputs.secondaryDnsServer].filter(Boolean);

  // 2. Install (parallel - both are network-bound)
  await timed('Install CoreDNS + mitmproxy', () =>
    Promise.all([installPackages(), installCoreDns(), installMitmproxy()])
  );

  // 3. Users, addon, policy, CA
  await createLogDirectory();
  const dnsUser = await createRandomDNSUser();
  const proxyUid = await createProxyUser();
  core.info(`DNS user ${dnsUser.username} (${dnsUser.uid}), proxy uid ${proxyUid}`);
  await installAddon();
  await writePolicy(policy);
  await generateCa();
  await installTeardownHelper();

  // 4. Proxy
  const proxyOpts = {
    port: ports.port,
    containerPort: ports.containerPort,
    streamLargeBodies: inputs.streamLargeBodies
  };
  await timed('Start proxy', () => startProxy(proxyOpts));

  // 5. Trust - before any traffic is forced through the proxy
  await timed('Install CA trust', async () => {
    await installSystemTrust();
    exportTrustEnv();
    await installJavaTrust();
  });

  // 6. DNS
  await timed('Configure DNS', async () => {
    // same names as the proxy: DNS and the proxy can never disagree about what is allowed
    await writeCorefile({
      mode,
      allow: [...policy.allow, ...policy.passthrough],
      deny: policy.deny,
      upstreams: dnsServers
    });
    await startCoreDns(dnsUser.username, DNS_READY_NAME);
    await setupDNSConfig();
    await restartResolved();
  });

  // 7. Docker. Containers get the container rules unless docker is about to be stopped. If
  // dockerd already did TLS (service/job container pulls), restart it so it trusts the CA (F1).
  const dockerActive = !inputs.stopDocker && (await isDockerActive());
  let dockerConfigWritten = false;
  if (dockerActive) {
    const services = await runningContainers();
    if (dockerRetained || services.length > 0) {
      dockerConfigWritten = await timed('Restart dockerd (CA trust)', () => restartDockerForCaTrust());
    }
  }

  // 8. Firewall
  await timed('Configure firewall', async () => {
    const prefixes = [LOG_PREFIX_DROP, LOG_PREFIX_ANALYZE, LOG_PREFIX_CDROP, LOG_PREFIX_CEGRESS].map(p => p.trim());
    await setupIptablesLogging(FIREWALL_LOG, prefixes, 'v2');
    await detectEgressInterface();
    await applyFirewall({
      mode,
      proxyUid,
      dnsUid: dnsUser.uid,
      proxyPort: ports.port,
      containerProxyPort: ports.containerPort,
      containers: dockerActive,
      dnsServers
    });
    await killPreexistingConnections();
    if (dockerActive) await flushContainerConntrack();
    await logFirewall();
  });

  // 9. Prove it on this runner
  const selfTestFrom = flowLogSize(FLOW_LOG);
  const dnsSelfTestName = dnsProbeName([...policy.allow, ...policy.passthrough]);
  const results = await timed('Self-tests', () => runSelfTests(mode, dnsSelfTestName));
  await new Promise(r => setTimeout(r, 500)); // let the probes' last records land
  const selfTestWindow = [selfTestFrom, flowLogSize(FLOW_LOG)];
  await exec.exec('sudo', ['tee', SELFTEST_FILE], { input: Buffer.from(JSON.stringify(results)), silent: true });
  await exec.exec('sudo', ['chmod', '0644', SELFTEST_FILE]);
  const failed = results.filter(r => !r.ok);
  if (failed.length > 0) {
    const msg = `self-test failed: ${failed.map(f => `${f.name} (${f.detail})`).join('; ')}`;
    if (mode === 'enforce') throw new Error(msg);
    core.warning(msg);
  }

  await exec.exec('sudo', ['tee', SETUP_MARKER], {
    input: Buffer.from(
      JSON.stringify({
        mode,
        sudoRetained,
        dockerRetained,
        containerTls: inputs.containerTls,
        containerRules: dockerActive,
        proxyPorts: [ports.port, ports.containerPort],
        selfTestWindow,
        dnsSelfTestName,
        at: new Date().toISOString()
      }) + '\n'
    ),
    silent: true
  });

  // 10. Privilege layer (carried from v1). Docker first: it needs sudo.
  if (inputs.stopDocker) {
    await stopDockerService();
  } else if (inputs.disableDocker) {
    await disableDockerForRunner();
  }
  await setupSudoLogging(SUDO_LOG, sudoFlavour);
  const validator = new SystemValidator([
    ...CRITICAL_FILES,
    getSudoLoggingConfigFile(sudoFlavour),
    ...(dockerConfigWritten ? [DOCKER_DAEMON_JSON] : [])
  ]);
  await validator.capturePostSetupBaseline();
  if (inputs.disableSudo) {
    await disableSudoForRunner(sudoFlavour);
  } else if (inputs.sudoConfig) {
    await applyCustomSudoConfig(inputs.sudoConfig, sudoFlavour);
  }

  core.info(`✅ safer-runner v2 active in ${mode} mode`);
}
