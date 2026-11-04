import * as core from '@actions/core';
import { SystemValidator, CRITICAL_FILES } from './validation';
import {
  type DnsUser,
  performInitialSetup,
  setupFirewallRules,
  setupDnsInterception,
  setupDNSConfig,
  setupDNSMasq,
  restartServices,
  finalizeFirewallRules,
  setupIptablesLogging
} from './setup';
import {
  removeSudoLogging,
  setupSudoLogging,
  disableSudoForRunner,
  applyCustomSudoConfig,
  detectSudoFlavour,
  getSudoLoggingConfigFile
} from './sudo';
import { disableDockerForRunner, stopDockerService } from './docker';
import { resolveGitHubDomains } from './parsers/github-parser';

async function run(): Promise<void> {
  try {
    const mode = core.getInput('mode') || 'analyze';
    const allowedDomains = core.getInput('allowed-domains') || '';
    const primaryDnsServer = core.getInput('primary-dns-server') || '9.9.9.9';
    // Honour an explicit empty secondary ("" disables it). action.yaml supplies the
    // Quad9 default when the input is unset, so we must NOT re-default here or the
    // documented "set secondary-dns-server: '' to disable" never works.
    const secondaryDnsServer = core.getInput('secondary-dns-server');
    const blockRiskySubdomains = core.getBooleanInput('block-risky-github-subdomains');
    const disableSudo = core.getBooleanInput('disable-sudo');
    const sudoConfig = core.getInput('sudo-config') || '';
    const disableDocker = core.getBooleanInput('disable-docker');
    const stopDocker = core.getBooleanInput('stop-docker');

    // Validate sudo-related inputs
    if (disableSudo && sudoConfig) {
      core.warning(
        '⚠️ Both disable-sudo and sudo-config are set. Ignoring sudo-config (disable-sudo takes precedence).'
      );
    }

    // Validate Docker-related inputs
    if (stopDocker && disableDocker) {
      core.warning('⚠️ Both stop-docker and disable-docker are set. stop-docker takes precedence (more restrictive).');
    }

    // Remove sudo logging config from pre-hook to stop capturing in pre-sudo.log
    await removeSudoLogging();

    // Ubuntu 25.10+ ships sudo-rs as the default sudo, which needs a different logging setup
    const sudoFlavour = await detectSudoFlavour();
    core.info(`Detected sudo implementation: ${sudoFlavour}`);

    core.info(`🛡️ Starting Safer Runner Action in ${mode} mode`);
    if (mode === 'enforce' && blockRiskySubdomains) {
      core.info('🔒 Risky GitHub subdomain blocking: ENABLED');
    }

    // Resolve the GitHub allowlist from api.github.com/meta while DNS still resolves
    // (the pre-hook's analyze mode, or the system resolver, still allows it here).
    // Falls back to the static list on failure.
    const { domains: githubDomains, source: githubDomainsSource } = await resolveGitHubDomains();
    core.info(`GitHub allowlist: ${githubDomains.length} domains (source: ${githubDomainsSource})`);

    // Check if pre-action already ran and set up infrastructure
    const preUsername = core.getState('dns-user');
    const preUid = core.getState('dns-uid');
    const preActionRan = preUsername && preUid;

    let dnsUser: DnsUser;

    if (!preActionRan) {
      // Pre-action didn't run - do full setup
      core.info('Pre-action did not run - performing full setup...');
      dnsUser = await performInitialSetup();

      // Setup rsyslog for main action iptables logs (pre-action would have already done this)
      core.info('Configuring iptables log filtering...');
      await setupIptablesLogging(
        '/var/log/safer-runner/main-iptables.log',
        ['Main-GitHub-Allow', 'Main-User-Allow', 'Main-Drop-Enforce', 'Main-Allow-Analyze'],
        'main'
      );
    } else {
      // Pre-action already set up infrastructure - just reconfigure
      core.info('✅ Pre-action already established monitoring infrastructure');
      dnsUser = {
        username: preUsername,
        uid: parseInt(preUid, 10)
      };

      // Setup rsyslog for main action iptables logs (separate from pre-hook logs)
      core.info('Configuring iptables log filtering for main action...');
      await setupIptablesLogging(
        '/var/log/safer-runner/main-iptables.log',
        ['Main-GitHub-Allow', 'Main-User-Allow', 'Main-Drop-Enforce', 'Main-Allow-Analyze'],
        'main'
      );
    }

    // Configure iptables rules with Main- log prefix
    core.info('Configuring iptables rules...');
    // Pass the configured DNS servers so the firewall allows exactly what dnsmasq
    // forwards to. Omitting them made enforce mode allow only Quad9 while dnsmasq
    // used the custom server, so every lookup was dropped (M1).
    await setupFirewallRules(dnsUser.uid, 'Main-', primaryDnsServer, secondaryDnsServer);

    // Force loopback-destined DNS (e.g. GitHub's egress resolver) through our dnsmasq
    await setupDnsInterception(dnsUser.uid);

    // Configure DNS filtering
    core.info('Configuring DNS filtering...');
    await setupDNSConfig();

    // Configure DNSMasq
    core.info('Configuring DNSMasq...');
    const blockedSubdomains = await setupDNSMasq(
      mode,
      allowedDomains,
      blockRiskySubdomains,
      dnsUser.username,
      '/var/log/safer-runner/main-dns.log',
      primaryDnsServer,
      secondaryDnsServer,
      githubDomains
    );

    if (blockedSubdomains.length > 0) {
      core.info('🛡️ Blocking risky GitHub subdomains in enforce mode:');
      for (const subdomain of blockedSubdomains) {
        core.info(`  🚫 Blocked: ${subdomain}`);
      }
    }

    // Start services
    core.info('Restarting services...');
    await restartServices('/var/log/safer-runner/main-dns.log');

    // Finalize firewall rules with Main- log prefix
    core.info('Finalizing firewall rules...');
    await finalizeFirewallRules(mode, 'Main-');

    // Handle Docker configuration BEFORE disabling sudo (Docker operations require sudo)
    if (stopDocker) {
      core.info('Stopping Docker service completely...');
      await stopDockerService();
    } else if (disableDocker) {
      core.info('Disabling Docker access for runner user...');
      await disableDockerForRunner();
    }

    // Setup sudo logging BEFORE restricting sudo - once restricted, the runner can
    // only run the read-only validation commands. The action's own commands from
    // here on are filtered out of the sudo report by parseSudoLogs().
    core.info('Configuring sudo logging for workflow monitoring...');
    await setupSudoLogging('/var/log/safer-runner/main-sudo.log', sudoFlavour);

    // Capture post-setup baseline for integrity monitoring (including sudo logging config)
    core.info('Capturing post-setup security baseline...');
    const validator = new SystemValidator([...CRITICAL_FILES, getSudoLoggingConfigFile(sudoFlavour)]);
    await validator.capturePostSetupBaseline();

    // Apply sudo restrictions last
    if (disableSudo) {
      core.info('Disabling sudo access for runner user...');
      await disableSudoForRunner(sudoFlavour);
    } else if (sudoConfig) {
      core.info('Applying custom sudo configuration...');
      await applyCustomSudoConfig(sudoConfig, sudoFlavour);
    }

    core.info(`✅ Safer Runner Action configured successfully in ${mode} mode`);
  } catch (error) {
    core.setFailed(`Action failed with error: ${error}`);
  }
}

run();
