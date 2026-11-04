/**
 * v2 setup orchestration. Runs once per job - in the pre step (so the policy is enforced for
 * every later action's pre-hook too, review H2), or in the main step if pre did not run.
 *
 * Order (each step depends on the previous):
 *   allowlist (api.github.com/meta, before DNS changes) -> install (dnsmasq + pinned mitmdump,
 *   in parallel) -> users -> addon + policy + CA -> start proxy (waits for the addon's own
 *   self-test) -> trust (system store, GITHUB_ENV, Java) -> DNS -> firewall (nat REDIRECT +
 *   filter) -> kill pre-existing :443 -> live self-tests -> docker -> sudo logging ->
 *   integrity baseline -> sudo restriction (last).
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import { DNS_LOG, FIREWALL_LOG, LOG_PREFIX_ANALYZE, LOG_PREFIX_DROP, SELFTEST_FILE, SUDO_LOG } from './constants';
import { applyFirewall, detectEgressInterface, killPreexistingConnections, logFirewall } from './firewall';
import type { Inputs } from './inputs';
import { buildPolicyConfig, dnsDomainsFor } from './policy';
import {
  createProxyUser,
  generateCa,
  installAddon,
  installMitmproxy,
  installTeardownHelper,
  startProxy,
  writePolicy
} from './proxy';
import { runSelfTests } from './selftest';
import {
  createLogDirectory,
  createRandomDNSUser,
  restartServices,
  setupDNSConfig,
  setupDNSMasq,
  setupIptablesLogging
} from './setup';
import { resolveGitHubDomains } from './parsers/github-parser';
import {
  applyCustomSudoConfig,
  detectSudoFlavour,
  disableSudoForRunner,
  getSudoLoggingConfigFile,
  setupSudoLogging
} from './sudo';
import { disableDockerForRunner, stopDockerService } from './docker';
import { exportTrustEnv, installJavaTrust, installSystemTrust } from './trust';
import { CRITICAL_FILES, SystemValidator } from './validation';

/** Root-owned marker written when setup completed; checked by main (pre may not have run). */
export const SETUP_MARKER = '/etc/safer-runner/setup-complete';

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

/** Install dnsmasq, only refreshing the apt index if a plain install fails (saves ~10s). */
export async function installDnsmasq(): Promise<void> {
  const opts = { ignoreReturnCode: true };
  const env = { ...process.env, DEBIAN_FRONTEND: 'noninteractive' } as { [key: string]: string };
  const install = ['apt-get', 'install', '-y', '-qq', '--no-install-recommends', 'dnsmasq'];
  if ((await exec.exec('sudo', ['-E', ...install], { ...opts, env })) === 0) return;
  await exec.exec('sudo', ['apt-get', 'update', '-qq']);
  await exec.exec('sudo', ['-E', ...install], { env });
}

export async function runSetup(inputs: Inputs): Promise<void> {
  const { mode } = inputs;
  core.info(`🛡️ safer-runner v2: ${mode.toUpperCase()} mode (L7 egress proxy)`);

  if (inputs.disableSudo && inputs.sudoConfig) {
    core.warning('Both disable-sudo and sudo-config are set. Ignoring sudo-config (disable-sudo takes precedence).');
  }
  if (inputs.stopDocker && inputs.disableDocker) {
    core.warning('Both stop-docker and disable-docker are set. stop-docker takes precedence.');
  }
  if (mode === 'enforce' && !inputs.disableSudo) {
    core.warning(
      'enforce mode without disable-sudo: any step can use sudo to remove the egress controls. ' +
        'Set disable-sudo: true (and disable-docker or stop-docker) to make enforce a real boundary.'
    );
  }

  const sudoFlavour = await detectSudoFlavour();
  core.info(`sudo implementation: ${sudoFlavour}`);

  // 1. Allowlist - fetched while normal DNS and direct egress still work
  const { domains: githubDomains, source } = await resolveGitHubDomains();
  core.info(`GitHub allowlist: ${githubDomains.length} domains (source: ${source})`);
  const { config: policy, warnings } = buildPolicyConfig({
    mode,
    githubDomains,
    allowedDomains: inputs.allowedDomains,
    passthroughDomains: inputs.passthroughDomains,
    blockRiskySubdomains: inputs.blockRiskySubdomains
  });
  for (const w of warnings) core.warning(w);
  core.info(
    `Policy: ${policy.allow.length} allowed, passthrough [${policy.passthrough.join(', ')}], deny [${policy.deny.join(', ')}]`
  );

  // 2. Install (parallel - both are network-bound)
  await timed('Install dnsmasq + mitmproxy', () => Promise.all([installDnsmasq(), installMitmproxy()]));

  // 3. Users, addon, policy, CA
  await createLogDirectory();
  const dnsUser = await createRandomDNSUser();
  const proxyUid = await createProxyUser();
  core.info(`dnsmasq user ${dnsUser.username} (${dnsUser.uid}), proxy uid ${proxyUid}`);
  await installAddon();
  await writePolicy(policy);
  await generateCa();
  await installTeardownHelper();

  // 4. Proxy
  const proxyOpts = { port: inputs.proxyPort, streamLargeBodies: inputs.streamLargeBodies };
  await timed('Start proxy', () => startProxy(proxyOpts));

  // 5. Trust - before any traffic is forced through the proxy
  await timed('Install CA trust', async () => {
    await installSystemTrust();
    exportTrustEnv();
    await installJavaTrust();
  });

  // 6. DNS
  await timed('Configure DNS', async () => {
    await setupDNSConfig();
    await setupDNSMasq(
      mode,
      '',
      inputs.blockRiskySubdomains,
      dnsUser.username,
      DNS_LOG,
      inputs.primaryDnsServer,
      inputs.secondaryDnsServer,
      dnsDomainsFor([...policy.allow, ...policy.passthrough])
    );
    await restartServices(DNS_LOG);
  });

  // 7. Firewall
  await timed('Configure firewall', async () => {
    await setupIptablesLogging(FIREWALL_LOG, [LOG_PREFIX_DROP.trim(), LOG_PREFIX_ANALYZE.trim()], 'v2');
    await detectEgressInterface();
    await applyFirewall({
      mode,
      proxyUid,
      dnsUid: dnsUser.uid,
      proxyPort: inputs.proxyPort,
      dnsServers: [inputs.primaryDnsServer, inputs.secondaryDnsServer].filter(Boolean)
    });
    await killPreexistingConnections();
    await logFirewall();
  });

  // 8. Prove it on this runner
  const results = await timed('Self-tests', () => runSelfTests(mode));
  await exec.exec('sudo', ['tee', SELFTEST_FILE], { input: Buffer.from(JSON.stringify(results)), silent: true });
  await exec.exec('sudo', ['chmod', '0644', SELFTEST_FILE]);
  const failed = results.filter(r => !r.ok);
  if (failed.length > 0) {
    const msg = `self-test failed: ${failed.map(f => `${f.name} (${f.detail})`).join('; ')}`;
    if (mode === 'enforce') throw new Error(msg);
    core.warning(msg);
  }

  await exec.exec('sudo', ['tee', SETUP_MARKER], {
    input: Buffer.from(JSON.stringify({ mode, at: new Date().toISOString() }) + '\n'),
    silent: true
  });

  // 9. Privilege layer (carried from v1). Docker first: it needs sudo.
  if (inputs.stopDocker) {
    await stopDockerService();
  } else if (inputs.disableDocker) {
    await disableDockerForRunner();
  }
  await setupSudoLogging(SUDO_LOG, sudoFlavour);
  const validator = new SystemValidator([...CRITICAL_FILES, getSudoLoggingConfigFile(sudoFlavour)]);
  await validator.capturePostSetupBaseline();
  if (inputs.disableSudo) {
    await disableSudoForRunner(sudoFlavour);
  } else if (inputs.sudoConfig) {
    await applyCustomSudoConfig(inputs.sudoConfig, sudoFlavour);
  }

  core.info(`✅ safer-runner v2 active in ${mode} mode`);
}
