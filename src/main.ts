import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { SystemValidator } from './validation';
import { buildDnsConfig, DEFAULT_DNS_SERVER } from './config/dns-config-builder';

async function run(): Promise<void> {
  try {
    const mode = core.getInput('mode') || 'analyze';
    const allowedDomains = core.getInput('allowed-domains') || '';
    const blockRiskySubdomains = core.getBooleanInput('block-risky-github-subdomains');

    core.info(`🛡️ Starting Safer Runner Action in ${mode} mode`);
    if (mode === 'enforce' && blockRiskySubdomains) {
      core.info('🔒 Risky GitHub subdomain blocking: ENABLED');
    }

    // Step 1: Install dependencies
    core.info('Installing dependencies...');
    await exec.exec('sudo', ['apt-get', 'update', '-qq']);
    await exec.exec('sudo', ['apt-get', 'install', '-y', 'dnsmasq', 'ipset']);

    // Step 2: Configure iptables rules
    core.info('Configuring iptables rules...');
    await setupFirewallRules();

    // Step 3: Configure DNS filtering
    core.info('Configuring DNS filtering...');
    await setupDNSConfig();

    // Step 4: Configure DNSMasq
    core.info('Configuring DNSMasq...');
    await setupDNSMasq(mode, allowedDomains, blockRiskySubdomains);

    // Step 5: Start services
    core.info('Starting services...');
    await startServices();

    // Step 6: Finalize security rules
    core.info('Finalizing security rules...');
    await finalizeSecurityRules(mode);

    // Step 7: Capture post-setup baseline for integrity monitoring
    core.info('Capturing post-setup security baseline...');
    const validator = new SystemValidator();
    await validator.capturePostSetupBaseline();

    core.info(`✅ Safer Runner Action configured successfully in ${mode} mode`);

  } catch (error) {
    core.setFailed(`Action failed with error: ${error}`);
  }
}

async function setupFirewallRules(): Promise<void> {
  // Allow established and related connections
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']);

  // Allow Azure metadata service (required for GitHub Actions)
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-d', '168.63.129.16', '-j', 'ACCEPT']);
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-d', '169.254.169.254', '-j', 'ACCEPT']);

  // Allow localhost traffic
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'lo', '-s', '127.0.0.1', '-d', '127.0.0.1', '-j', 'ACCEPT']);

  // Log processing for debugging
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-j', 'LOG', '--log-prefix=Processing: ']);

  // Create ipset for GitHub Actions required domains
  await exec.exec('sudo', ['ipset', 'create', 'github', 'hash:ip']);
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'set', '--match-set', 'github', 'dst', '-j', 'LOG', '--log-prefix=GitHub-Allow: ']);
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'set', '--match-set', 'github', 'dst', '-j', 'ACCEPT']);

  // Create ipset for user allowed domains
  await exec.exec('sudo', ['ipset', 'create', 'user', 'hash:ip']);
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'set', '--match-set', 'user', 'dst', '-j', 'LOG', '--log-prefix=User-Allow: ']);
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'set', '--match-set', 'user', 'dst', '-j', 'ACCEPT']);
}

async function setupDNSConfig(): Promise<void> {
  // Configure systemd-resolved to use our DNS server
  await exec.exec('sudo', ['mkdir', '-p', '/etc/systemd/resolved.conf.d']);

  const resolvedConfig = `[Resolve]
DNS=127.0.0.1
DNSSEC=yes
DNSStubListener=no`;

  await exec.exec('sudo', ['tee', '/etc/systemd/resolved.conf.d/no-stub.conf'], {
    input: Buffer.from(resolvedConfig)
  });

  // Update resolv.conf to use localhost
  await exec.exec('sudo', ['unlink', '/etc/resolv.conf']);
  await exec.exec('sudo', ['tee', '/etc/resolv.conf'], {
    input: Buffer.from('nameserver 127.0.0.1\n')
  });
}

async function setupDNSMasq(mode: string, allowedDomains: string, blockRiskySubdomains: boolean): Promise<void> {
  // Build DNS configuration using the config builder module
  const { config: dnsmasqConfig, blockedSubdomains } = buildDnsConfig({
    mode: mode as 'analyze' | 'enforce',
    allowedDomains,
    blockRiskySubdomains
  });

  // Log blocked subdomains if any
  if (blockedSubdomains.length > 0) {
    core.info('🛡️ Blocking risky GitHub subdomains in enforce mode:');
    for (const subdomain of blockedSubdomains) {
      core.info(`  🚫 Blocked: ${subdomain}`);
    }
  }

  // Write configuration to file
  await exec.exec('sudo', ['tee', '/etc/dnsmasq.conf'], {
    input: Buffer.from(dnsmasqConfig)
  });
}

async function startServices(): Promise<void> {
  // Restart systemd-resolved and start dnsmasq
  await exec.exec('sudo', ['systemctl', 'restart', 'systemd-resolved']);
  await exec.exec('sudo', ['systemctl', 'enable', 'dnsmasq']);
  await exec.exec('sudo', ['systemctl', 'start', 'dnsmasq']);

  // Allow DNS traffic to our upstream server
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-d', DEFAULT_DNS_SERVER, '-p', 'udp', '--dport', '53', '-m', 'owner', '--uid-owner', 'dnsmasq', '-j', 'ACCEPT']);
}

async function finalizeSecurityRules(mode: string): Promise<void> {
  if (mode === 'enforce') {
    // Log dropped packets for debugging
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'LOG', '--log-prefix=Drop-Enforce: ']);

    // DEFAULT DENY: Drop external traffic not explicitly allowed (scoped to eth0)
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'DROP']);
  } else {
    // Log other traffic for analysis but allow it
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-j', 'LOG', '--log-prefix=Allow-Analyze: ']);
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-j', 'ACCEPT']);
  }
}

run();