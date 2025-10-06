import * as core from '@actions/core';
import { SystemValidator } from './validation';
import {
  type DnsUser,
  performInitialSetup,
  setupFirewallRules,
  setupDNSConfig,
  setupDNSMasq,
  restartServices,
  finalizeFirewallRules,
  setupIptablesLogging
} from './setup';
import { removeSudoLogging, setupSudoLogging, disableSudoForRunner, applyCustomSudoConfig } from './sudo';

async function run(): Promise<void> {
  try {
    const mode = core.getInput('mode') || 'analyze';
    const allowedDomains = core.getInput('allowed-domains') || '';
    const blockRiskySubdomains = core.getBooleanInput('block-risky-github-subdomains');
    const disableSudo = core.getBooleanInput('disable-sudo');
    const sudoConfig = core.getInput('sudo-config') || '';

    // Validate sudo-related inputs
    if (disableSudo && sudoConfig) {
      core.warning(
        '⚠️ Both disable-sudo and sudo-config are set. Ignoring sudo-config (disable-sudo takes precedence).'
      );
    }

    // Remove sudo logging config from pre-hook to stop capturing in pre-sudo.log
    await removeSudoLogging();

    core.info(`🛡️ Starting Safer Runner Action in ${mode} mode`);
    if (mode === 'enforce' && blockRiskySubdomains) {
      core.info('🔒 Risky GitHub subdomain blocking: ENABLED');
    }

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
    await setupFirewallRules(dnsUser.uid, 'Main-');

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
      '/var/log/safer-runner/main-dns.log'
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

    // Capture post-setup baseline for integrity monitoring
    core.info('Capturing post-setup security baseline...');
    const validator = new SystemValidator();
    await validator.capturePostSetupBaseline();

    // Apply sudo configuration FIRST to set up exclusion rules
    // This must happen BEFORE setupSudoLogging() so that internal setup commands
    // are excluded from logs via Defaults!SAFER_RUNNER_CONFIG !log_allowed
    if (disableSudo) {
      core.info('Disabling sudo access for runner user...');
      await disableSudoForRunner();
    } else if (sudoConfig) {
      core.info('Applying custom sudo configuration...');
      await applyCustomSudoConfig(sudoConfig);
    } else {
      // No custom config - apply default config to set up exclusion rules
      core.info('Configuring default sudo access with validation exclusions...');
      await applyCustomSudoConfig();
    }

    // Setup sudo logging AFTER exclusion rules are in place
    // This ensures internal setup commands are not logged
    core.info('Configuring sudo logging for workflow monitoring...');
    await setupSudoLogging('/var/log/safer-runner/main-sudo.log');

    core.info(`✅ Safer Runner Action configured successfully in ${mode} mode`);
  } catch (error) {
    core.setFailed(`Action failed with error: ${error}`);
  }
}

run();
