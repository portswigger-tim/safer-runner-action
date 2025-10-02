import * as core from '@actions/core';
import * as exec from '@actions/exec';
import {
  createRandomDNSUser,
  setupFirewallRules,
  setupDNSConfig,
  setupDNSMasq,
  restartServices,
  finalizeFirewallRules
} from './setup';

/**
 * Pre-action hook: Establish security in analyze mode
 *
 * This runs BEFORE the main action step, providing early network monitoring.
 *
 * Strategy:
 * - Set up full security infrastructure in ANALYZE mode (log everything, block nothing)
 * - Main action will reconfigure to user's desired mode (analyze or enforce)
 * - Save DNS user info in state for main action to reuse
 */
async function run(): Promise<void> {
  try {
    core.info('🔍 Pre-action: Establishing security monitoring...');

    // Step 1: Install dependencies
    core.info('Installing dependencies...');
    await exec.exec('sudo', ['apt-get', 'update', '-qq']);
    await exec.exec('sudo', ['apt-get', 'install', '-y', 'dnsmasq', 'ipset']);

    // Step 2: Create random DNS user for privilege separation
    core.info('Creating isolated DNS user...');
    const dnsUser = await createRandomDNSUser();

    // Save DNS user info for main action to use
    core.saveState('dns-user', dnsUser.username);
    core.saveState('dns-uid', dnsUser.uid.toString());
    core.info(`Created isolated DNS user: ${dnsUser.username} (UID: ${dnsUser.uid})`);

    // Step 3: Configure iptables rules with Pre- log prefix
    core.info('Configuring iptables rules...');
    await setupFirewallRules(dnsUser.uid, 'Pre-');

    // Step 4: Configure DNS filtering
    core.info('Configuring DNS filtering...');
    await setupDNSConfig();

    // Step 5: Configure DNSMasq in ANALYZE mode (permissive, log everything)
    core.info('Configuring DNSMasq in analyze mode...');
    await setupDNSMasq('analyze', '', false, dnsUser.username);

    // Step 6: Start services
    core.info('Restarting services...');
    await restartServices();

    // Step 7: Finalize with ANALYZE mode rules (log but allow all) with Pre- log prefix
    core.info('Finalizing analyze mode rules...');
    await finalizeFirewallRules('analyze', 'Pre-');

    core.info('✅ Pre-action: Security monitoring active (analyze mode)');
    core.info('   Main action will apply user configuration...');

  } catch (error) {
    // Don't fail the workflow if pre-setup fails - log warning and continue
    core.warning(`Pre-action setup encountered an error: ${error}`);
    core.warning('Main action will attempt full setup...');
  }
}

run();
