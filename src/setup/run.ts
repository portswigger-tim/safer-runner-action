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
import { FLOW_LOG, DOCKER_DAEMON_JSON, SELFTEST_FILE, SUDO_LOG } from '../constants';
import { flowLogSize } from '../flowlog';
import * as iptables from '../services/iptables';
import type { Inputs } from '../config/inputs';
import { CONTAINER_TLS, buildPolicyConfig } from '../policy';
import * as mitmproxy from '../services/mitmproxy';
import { generateCa } from '../services/mitmproxy/ca';
import { distributeTrust } from '../services/mitmproxy/trust';
import { dnsProbeName, runSelfTests } from './selftest';
import * as coredns from '../services/coredns';
import { realHost, type Host } from '../system/host';
import { resolveGitHubDomains } from '../config/github-domains';
import * as sudo from '../services/sudo';
import * as docker from '../services/docker';
import { CRITICAL_FILES, captureBaseline } from '../integrity/baseline';

/** Root-owned marker written when setup completed; checked by main (pre may not have run). */
export const SETUP_MARKER = '/etc/safer-runner/setup-complete';

/**
 * Create /var/log/safer-runner directory with proper permissions
 * This directory will contain all safer-runner log files (DNS, iptables, sudo)
 */
async function createLogDirectory(): Promise<void> {
  const logDir = '/var/log/safer-runner';

  // Create directory
  await exec.exec('sudo', ['mkdir', '-p', logDir]);

  // Set ownership to syslog:adm (rsyslog runs as syslog, runner is in adm group)
  await exec.exec('sudo', ['chown', 'syslog:adm', logDir]);

  // Make directory readable by all (so runner can read logs without sudo)
  await exec.exec('sudo', ['chmod', '755', logDir]);
}

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

/**
 * `h` is where the converted services run their commands. Until every step takes a Host (the
 * integrity baseline and a few setup steps here still use @actions/exec directly), it is a test
 * seam only: pass anything but realHost and part of setup still runs on the real machine.
 */
export async function runSetup(inputs: Inputs, h: Host = realHost): Promise<void> {
  const { mode } = inputs;
  core.info(`🛡️ safer-runner v2: ${mode.toUpperCase()} mode (L7 egress proxy)`);

  if (inJobContainer()) {
    if (mode === 'enforce') throw new Error(JOB_CONTAINER_MESSAGE);
    core.warning(`${JOB_CONTAINER_MESSAGE} Analyze mode: nothing is monitored in this job.`, {
      title: 'safer-runner: job container not supported'
    });
    return;
  }

  // enforce without sudo removal is advisory: any step can sudo the controls away (review H2)
  const sudoRetained = mode === 'enforce' && !inputs.disableSudo;
  if (sudoRetained) {
    core.warning(
      'enforce is ADVISORY in this job: sudo is retained (disable-sudo: false), so any step can use it to ' +
        'remove the egress controls. This is not an enforced boundary. Remove disable-sudo: false to make ' +
        'enforce a boundary.',
      { title: 'safer-runner: enforce (ADVISORY - sudo retained)' }
    );
  } else if (mode === 'enforce' && inputs.disableSudoDefaulted) {
    core.info('disable-sudo not set: enforce mode removes sudo by default (set disable-sudo: false to keep it)');
  }
  for (const w of sudo.sudoConfigWarnings(inputs.sudoConfig, sudo.runnerWritableDirs())) core.warning(w);
  if (mode === 'analyze' && inputs.disableSudo && !inputs.disableSudoDefaulted) {
    core.warning(
      'disable-sudo: true is not applied in analyze mode: analyze never changes sudo. The summary lists the ' +
        'sudo commands enforce would block. Use mode: enforce to remove sudo.',
      { title: 'safer-runner: analyze does not remove sudo' }
    );
  }
  if (mode === 'enforce' && inputs.disableSudo && inputs.sudoConfig.length) {
    // D1: never a boundary - no allowlist can be proven free of a command that gives root
    core.warning(
      `enforce is ADVISORY in this job: sudo-config keeps ${inputs.sudoConfig.length} sudo command ` +
        'line(s), and a command that can run code or write files gives the job root, which can remove ' +
        'the egress controls. Remove sudo-config to make enforce a boundary.',
      { title: 'safer-runner: enforce (ADVISORY - sudo allowlist)' }
    );
  }
  if (mode === 'enforce' && inputs.dockerDefaulted) {
    core.info('docker not set: enforce mode removes docker access by default (docker: remove-group)');
  }
  // analyze never changes docker access: it evaluates the policy in the post step
  const dockerPlan = docker.planDocker(mode, inputs.docker);
  if (mode === 'analyze' && inputs.docker !== 'keep' && !inputs.dockerDefaulted) {
    core.warning(
      `docker: ${inputs.docker} is not applied in analyze mode: analyze never changes docker access. Use ` +
        `mode: enforce to ${inputs.docker === 'stop' ? 'stop docker' : 'remove docker access'}.`,
      { title: 'safer-runner: analyze does not change docker' }
    );
  }

  const sudoFlavour = await sudo.detectSudoFlavour(h);
  core.info(`sudo implementation: ${sudoFlavour}`);

  const ports = await mitmproxy.allocateProxyPorts();
  core.info(`Proxy listeners: host 127.0.0.1:${ports.port}, containers 127.0.0.1:${ports.containerPort}`);

  // 1. Allowlist - fetched while normal DNS and direct egress still work
  const { domains: githubDomains, source } = await resolveGitHubDomains();
  core.info(`GitHub allowlist: ${githubDomains.length} domains (source: ${source})`);
  const {
    config: policy,
    warnings,
    user
  } = buildPolicyConfig({
    mode,
    githubDomains,
    allowedDomains: inputs.allowedDomains,
    passthroughDomains: inputs.passthroughDomains,
    blockRiskySubdomains: inputs.blockRiskySubdomains,
    containerPort: ports.containerPort,
    httpFilter: inputs.httpFilter,
    allowGithubPlatform: inputs.allowGithubPlatform
  });
  for (const w of warnings) core.warning(w);
  core.info(
    `Policy: ${policy.allow.length} allowed, passthrough [${policy.passthrough.join(', ')}], deny [${policy.deny.join(', ')}]`
  );
  if (policy.http_filter.hosts.length) {
    core.info(
      `http-filter: ${policy.http_filter.hosts.length} filtered host(s) [${policy.http_filter.hosts.map(h => h.host).join(', ')}], ` +
        `${policy.http_filter.platform_auto_allowed} platform endpoint(s) auto-allowed, ` +
        `${policy.http_filter.platform_optional} more unless a rule of the job's matches`
    );
  }

  const { dnsServers } = inputs;

  // 2. Install (parallel - both are network-bound)
  await timed('Install CoreDNS + mitmproxy', () =>
    Promise.all([installPackages(), coredns.install(h), mitmproxy.install(h)])
  );

  // 3. Users, addon, policy, CA
  await createLogDirectory();
  const dnsUser = await coredns.createUser(h);
  const proxyUid = await mitmproxy.ensureUser(h);
  core.info(`DNS user ${dnsUser.username} (${dnsUser.uid}), proxy uid ${proxyUid}`);
  const proxyRendered = mitmproxy.render({ policy, ports });
  const proxyConfig = await mitmproxy.writeConfig(h, proxyRendered);
  const ca = await generateCa(h);

  // 4. Proxy
  const proxy = await timed('Start proxy', () => mitmproxy.start(h, proxyRendered, ports, proxyConfig, ca));

  // 5. Trust - before any traffic is forced through the proxy (`trust` is also the dockerd
  // restart's precondition once docker takes tokens)
  const trust = await timed('Install CA trust', () => distributeTrust(h, proxy));

  // 6. DNS: CoreDNS answering first, then the system resolver points at it
  const resolver = await timed('Configure DNS', async () => {
    const dns = await coredns.start(
      h,
      coredns.render({
        mode,
        // same names as the proxy: DNS and the proxy can never disagree about what is allowed
        allow: [...policy.allow, ...policy.passthrough],
        deny: policy.deny,
        upstreams: dnsServers,
        // read before the cutover, while the VM's hostname still resolves the original way
        hosts: await coredns.localHosts(),
        user: dnsUser.username
      })
    );
    return coredns.cutover(h, dns);
  });

  // 7. Docker. Containers get the container rules unless docker is about to be stopped. If
  // dockerd already did TLS (service/job container pulls), restart it so it trusts the CA (F1).
  const dockerd = await docker.prepare(h, dockerPlan.applied, trust);

  // 8. Firewall: only once the resolver points at CoreDNS, the CA is trusted and dockerd settled
  const { containerRules, firewall } = await timed('Configure firewall', () =>
    iptables.configure(
      h,
      {
        mode,
        proxyUid,
        dnsUid: dnsUser.uid,
        proxyPort: ports.port,
        containerProxyPort: ports.containerPort,
        containers: dockerd.active,
        dnsServers
      },
      { resolver, trust, docker: dockerd.prepared }
    )
  );

  // 9. Prove it on this runner
  const selfTestFrom = flowLogSize(FLOW_LOG);
  const dnsSelfTestName = dnsProbeName([...policy.allow, ...policy.passthrough]);
  const { results, selfTests } = await timed('Self-tests', () => runSelfTests(mode, dnsSelfTestName, firewall));
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

  // 10. Privilege layer (carried from v1). Docker first: it needs sudo.
  const dockerAccess = await docker.applyAccessPolicy(h, dockerPlan, selfTests);
  // analyze: record the use of docker from here on, for the post step's docker evaluation
  const dockerEvents =
    mode === 'analyze' && dockerd.active ? await docker.startEventRecorder(h, dockerd.prepared) : null;
  await exec.exec('sudo', ['tee', SETUP_MARKER], {
    input: Buffer.from(
      JSON.stringify({
        mode,
        sudoRetained,
        // the sudo policy the post step evaluates (analyze) or reports (enforce)
        ...(inputs.sudoConfig.length ? { sudoConfig: inputs.sudoConfig.map(sudo.ruleText) } : {}),
        ...(mode === 'analyze' && !inputs.disableSudo ? { sudoKept: true } : {}),
        // the job's own allowlist as applied: the post step suggests from it, never from inputs
        // read again at post time
        allowedDomains: user.allowed,
        passthroughDomains: user.passthrough,
        dockerRetained: dockerAccess.access === 'retained',
        // the summary shows the dockerd restart for CA trust (F1) as the action's own docker change
        docker: { ...dockerAccess, caRestart: dockerd.restarted },
        ...(dockerEvents ? { dockerEvents } : {}),
        failOnTampering: inputs.failOnTampering,
        containerTls: CONTAINER_TLS,
        containerRules,
        proxyPorts: [ports.port, ports.containerPort],
        selfTestWindow,
        dnsSelfTestName,
        at: new Date().toISOString()
      }) + '\n'
    ),
    silent: true
  });
  // 11. Sudo: logging on, then the integrity baseline, then sudo restricted - the last step
  const sudoRendered = sudo.render({
    flavour: sudoFlavour,
    logFile: SUDO_LOG,
    // analyze never changes sudo: it evaluates the policy in the post step
    restrict: mode === 'enforce' && inputs.disableSudo,
    rules: inputs.sudoConfig
  });
  const sudoLogging = await sudo.setupSudoLogging(h, sudoRendered);
  const baseline = await captureBaseline(
    h,
    [...CRITICAL_FILES, sudoRendered.logging.path, ...(dockerd.configWritten ? [DOCKER_DAEMON_JSON] : [])],
    sudoLogging
  );
  if (sudoRendered.restrict) {
    await sudo.restrictSudo(h, sudoRendered, baseline);
  }

  core.info(`✅ safer-runner v2 active in ${mode} mode`);
}
