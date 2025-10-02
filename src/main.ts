import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { SystemValidator } from './validation';
import {
  type DnsUser,
  createRandomDNSUser,
  setupFirewallRules,
  setupDNSConfig,
  setupDNSMasq,
  startServices,
  finalizeSecurityRules
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
      await exec.exec('bash', ['-c', 'sudo grep dnsmasq /var/log/syslog > /tmp/pre-hook-dns-logs.txt || true']);
      core.info('✅ Pre-hook DNS logs saved to /tmp/pre-hook-dns-logs.txt');
    }

    let dnsUser: DnsUser;

    if (preActionRan) {
      // Pre-action already set up infrastructure - just reconfigure
      core.info('✅ Pre-action already established monitoring infrastructure');
      dnsUser = {
        username: preUsername,
        uid: parseInt(preUid, 10)
      };

      // Only need to reconfigure if user wants enforce mode or custom settings
      if (mode === 'enforce' || allowedDomains || blockRiskySubdomains) {
        core.info('Reconfiguring security policies...');

        // Reconfigure DNSMasq with user settings
        const blockedSubdomains = await setupDNSMasq(mode, allowedDomains, blockRiskySubdomains, dnsUser.username);

        if (blockedSubdomains.length > 0) {
          core.info('🛡️ Blocking risky GitHub subdomains in enforce mode:');
          for (const subdomain of blockedSubdomains) {
            core.info(`  🚫 Blocked: ${subdomain}`);
          }
        }

        // Restart dnsmasq to apply new config
        await exec.exec('sudo', ['systemctl', 'restart', 'dnsmasq']);

        // Reconfigure iptables final rules
        if (mode === 'enforce') {
          core.info('Applying enforce mode firewall rules...');
          // Remove the analyze mode ACCEPT rule (pre-action uses Pre- prefix)
          await exec.exec('sudo', ['iptables', '-D', 'OUTPUT', '-j', 'LOG', '--log-prefix=Pre-Allow-Analyze: ']);
          await exec.exec('sudo', ['iptables', '-D', 'OUTPUT', '-j', 'ACCEPT']);
          // Add enforce mode DROP rule
          await finalizeSecurityRules('enforce');
        }
      }
    } else {
      // Pre-action didn't run - do full setup
      core.info('Pre-action did not run - performing full setup...');

      // Step 1: Install dependencies
      core.info('Installing dependencies...');
      await exec.exec('sudo', ['apt-get', 'update', '-qq']);
      await exec.exec('sudo', ['apt-get', 'install', '-y', 'dnsmasq', 'ipset']);

      // Step 2: Create random DNS user for privilege separation
      core.info('Creating isolated DNS user...');
      dnsUser = await createRandomDNSUser();
      core.info(`Created isolated DNS user: ${dnsUser.username} (UID: ${dnsUser.uid})`);

      // Step 3: Configure iptables rules
      core.info('Configuring iptables rules...');
      await setupFirewallRules();

      // Step 4: Configure DNS filtering
      core.info('Configuring DNS filtering...');
      await setupDNSConfig();

      // Step 5: Configure DNSMasq
      core.info('Configuring DNSMasq...');
      const blockedSubdomains = await setupDNSMasq(mode, allowedDomains, blockRiskySubdomains, dnsUser.username);

      if (blockedSubdomains.length > 0) {
        core.info('🛡️ Blocking risky GitHub subdomains in enforce mode:');
        for (const subdomain of blockedSubdomains) {
          core.info(`  🚫 Blocked: ${subdomain}`);
        }
      }

      // Step 6: Start services
      core.info('Starting services...');
      await startServices(dnsUser.uid);

      // Step 7: Finalize security rules
      core.info('Finalizing security rules...');
      await finalizeSecurityRules(mode);
    }

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