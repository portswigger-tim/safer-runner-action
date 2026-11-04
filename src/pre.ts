import * as core from '@actions/core';
import * as exec from '@actions/exec';
import {
  performInitialSetup,
  setupFirewallRules,
  setupDnsInterception,
  setupDNSConfig,
  setupDNSMasq,
  restartServices,
  finalizeFirewallRules,
  setupSudoLogging,
  setupIptablesLogging
} from './setup';
import { resolveGitHubDomains } from './parsers/github-parser';

/**
 * Pre-action hook: Establish security in analyze mode
 *
 * This runs BEFORE the main action oviding early network monitoring.
 *
 * Strategy:
 * - Set up full security infrastructure in ANALYZE mode (log everything, block nothing)
 * - Main action will reconfigure to user's desired mode (analyze or enforce)
 * - Save DNS user info in state for main action to reuse
 */
async function run(): Promise<void> {
  try {
    core.info('🔍 Pre-action: Establishing security monitoring...');

    // Resolve the GitHub allowlist from api.github.com/meta while normal DNS still
    // works (before we repoint resolv.conf). Falls back to the static list on failure.
    const { domains: githubDomains, source: githubDomainsSource } = await resolveGitHubDomains();
    core.info(`GitHub allowlist: ${githubDomains.length} domains (source: ${githubDomainsSource})`);

    // Perform initial system setup
    const dnsUser = await performInitialSetup();

    // Save DNS user info for main action to use
    core.saveState('dns-user', dnsUser.username);
    core.saveState('dns-uid', dnsUser.uid.toString());

    // Setup rsyslog to filter pre-hook iptables logs to dedicated file
    core.info('Configuring iptables log filtering...');
    await setupIptablesLogging(
      '/var/log/safer-runner/pre-iptables.log',
      ['Pre-GitHub-Allow', 'Pre-User-Allow', 'Pre-Allow-Analyze'],
      'pre'
    );

    // Configure iptables rules with Pre- log prefix
    core.info('Configuring iptables rules...');
    await setupFirewallRules(dnsUser.uid, 'Pre-');

    // Force loopback-destined DNS (e.g. GitHub's egress resolver) through our dnsmasq
    await setupDnsInterception(dnsUser.uid);

    // Configure DNS filtering
    core.info('Configuring DNS filtering...');
    await setupDNSConfig();

    // Configure DNSMasq in ANALYZE mode (permissive, log everything)
    core.info('Configuring DNSMasq in analyze mode...');
    await setupDNSMasq(
      'analyze',
      '',
      false,
      dnsUser.username,
      '/var/log/safer-runner/pre-dns.log',
      undefined,
      undefined,
      githubDomains
    );

    // Start services
    core.info('Restarting services...');
    await restartServices('/var/log/safer-runner/pre-dns.log');

    // Finalize with ANALYZE mode rules (log but allow all) with Pre- log prefix
    core.info('Finalizing analyze mode rules...');
    await finalizeFirewallRules('analyze', 'Pre-');

    // Setup sudo logging last so setup commands are not captured
    // This captures sudo usage by other actions' pre-hooks
    core.info('Configuring sudo logging for pre-hook monitoring...');
    await setupSudoLogging('/var/log/safer-runner/pre-sudo.log');

    core.info('✅ Pre-action: Security monitoring active (analyze mode)');
    core.info('   Main action will apply user configuration...');
  } catch (error) {
    // Don't fail the workflow if pre-setup fails - log warning and continue
    core.warning(`Pre-action setup encountered an error: ${error}`);
    core.warning('Main action will attempt full setup...');
  }
}

run();
