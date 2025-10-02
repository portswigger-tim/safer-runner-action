import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { SystemValidator } from './validation';
import {
  type DnsUser,
  createRandomDNSUser,
  setupFirewallRules,
  setupDNSConfig,
  setupDNSMasq,
  restartServices,
  finalizeFirewallRules,
  setupIpsets
} from './setup';

async function run(): Promise<void> {
  try {
    const mode = core.getInput('mode') || 'analyze';
    const allowedDomains = core.getInput('allowed-domains') || '';
    const blockRiskySubdomains = core.getBooleanInput('block-risky-github-subdomains');

    core.info(`🛡️ Starting Safer Runner Action in ${mode} mode`);
    if (mode === 'enforce' && blockRiskySubdomains) {
      core.info('🔒 Risky GitHub subdomain blocking: ENABLED');
    }

    // Check if pre-action already ran and set up infrastructure
    const preUsername = core.getState('dns-user');
    const preUid = core.getState('dns-uid');
    const preActionRan = preUsername && preUid;

    // If pre-action ran, capture its DNS logs before we reconfigure
    if (preActionRan) {
      core.info('📋 Capturing pre-hook DNS logs...');
      await exec.exec('bash', ['-c', 'sudo grep dnsmasq /var/log/syslog | tee /tmp/pre-hook-dns-logs.txt || true']);
      core.info('✅ Pre-hook DNS logs saved to /tmp/pre-hook-dns-logs.txt');
    }

    let dnsUser: DnsUser;
    
    if(!preActionRan) {
      // Pre-action didn't run - do full setup
      core.info('Pre-action did not run - performing full setup...');

      // Install dependencies
      core.info('Installing dependencies...');
      await exec.exec('sudo', ['apt-get', 'update', '-qq']);
      await exec.exec('sudo', ['apt-get', 'install', '-y', 'dnsmasq', 'ipset']);

      // Create random DNS user for privilege separation
      core.info('Creating isolated DNS user...');
      dnsUser = await createRandomDNSUser();
      core.info(`Created isolated DNS user: ${dnsUser.username} (UID: ${dnsUser.uid})`);

      // Configure ipsets
      core.info('Configuring ipsets...');
      await setupIpsets();
    } else {
      // Pre-action already set up infrastructure - just reconfigure
      core.info('✅ Pre-action already established monitoring infrastructure');
      dnsUser = {
        username: preUsername,
        uid: parseInt(preUid, 10)
      };
    }

    // Configure iptables rules
    core.info('Configuring iptables rules...');
    await setupFirewallRules(dnsUser.uid);

    // Configure DNS filtering
    core.info('Configuring DNS filtering...');
    await setupDNSConfig();

    // Configure DNSMasq
    core.info('Configuring DNSMasq...');
    const blockedSubdomains = await setupDNSMasq(mode, allowedDomains, blockRiskySubdomains, dnsUser.username);

    if (blockedSubdomains.length > 0) {
      core.info('🛡️ Blocking risky GitHub subdomains in enforce mode:');
      for (const subdomain of blockedSubdomains) {
        core.info(`  🚫 Blocked: ${subdomain}`);
      }
    }

    // Start services
    core.info('Restarting services...');
    await restartServices();

    // Finalize firewall rules
    core.info('Finalizing firewall rules...');
    await finalizeFirewallRules(mode);

    // Capture post-setup baseline for integrity monitoring
    core.info('Capturing post-setup security baseline...');
    const validator = new SystemValidator();
    await validator.capturePostSetupBaseline();

    core.info(`✅ Safer Runner Action configured successfully in ${mode} mode`);

  } catch (error) {
    core.setFailed(`Action failed with error: ${error}`);
  }
}

run();