/**
 * Shared setup functions for pre and main actions
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as crypto from 'crypto';
import { buildDnsConfig, DEFAULT_DNS_SERVER } from './config/dns-config-builder';

export interface DnsUser {
  username: string;
  uid: number;
}

/**
 * Configure sudo logging to capture all sudo usage
 * Logs to /tmp/runner-sudo.log for visibility and auditability
 */
export async function setupSudoLogging(): Promise<void> {
  core.info('Configuring sudo logging...');

  // Create a sudoers.d file to enable logging
  const logConfig = 'Defaults logfile=/tmp/runner-sudo.log\n';

  await exec.exec('sudo', ['tee', '/etc/sudoers.d/00-sudo-logging'], {
    input: Buffer.from(logConfig)
  });

  // Set appropriate permissions (must be 0440 or 0400 for sudoers files)
  await exec.exec('sudo', ['chmod', '0440', '/etc/sudoers.d/00-sudo-logging']);
  await exec.exec('sudo', ['chown', 'root:root', '/etc/sudoers.d/00-sudo-logging']);

  // Create the log file and make it readable by the runner
  await exec.exec('sudo', ['touch', '/tmp/runner-sudo.log']);
  await exec.exec('sudo', ['chmod', '0644', '/tmp/runner-sudo.log']);

  core.info('✅ Sudo logging configured to /tmp/runner-sudo.log');
}

/**
 * Disable sudo access for the runner user
 * This prevents malicious code from using sudo to bypass security controls
 *
 * The runner user on GitHub Actions has sudo access via /etc/sudoers.d/runner
 * which contains: runner ALL=(ALL) NOPASSWD:ALL
 *
 * Renaming this file effectively disables all sudo access for the runner user.
 */
export async function disableSudoForRunner(): Promise<void> {
  // Get the current user (should be 'runner' on GitHub Actions)
  let currentUser = '';
  await exec.exec('whoami', [], {
    listeners: {
      stdout: (data: Buffer) => {
        currentUser += data.toString().trim();
      }
    }
  });

  core.info(`Disabling sudo access for user: ${currentUser}`);

  // GitHub Actions runners grant sudo via /etc/sudoers.d/runner file
  const sudoersFile = `/etc/sudoers.d/${currentUser}`;
  const disabledFile = `${sudoersFile}.disabled-by-safer-runner`;

  try {
    // Check if the sudoers file exists
    await exec.exec('sudo', ['test', '-f', sudoersFile]);

    // Rename it to disable sudo access (preserves file for debugging)
    await exec.exec('sudo', ['mv', sudoersFile, disabledFile]);

    core.info(`✅ Renamed ${sudoersFile} to ${disabledFile}`);
    core.info('🔒 Sudo access disabled - runner user can no longer execute privileged commands');
  } catch (error) {
    core.warning(`Could not disable sudo: ${error}`);
    core.warning(`File ${sudoersFile} may not exist`);
  }
}

/**
 * Perform initial system setup: install dependencies, configure sudo logging, create DNS user, setup ipsets
 * Returns the created DNS user
 */
export async function performInitialSetup(): Promise<DnsUser> {
  // Install dependencies
  core.info('Installing dependencies...');
  await exec.exec('sudo', ['apt-get', 'update', '-qq']);
  await exec.exec('sudo', ['apt-get', 'install', '-y', 'dnsmasq', 'ipset']);

  // Configure sudo logging
  await setupSudoLogging();

  // Create random DNS user for privilege separation
  core.info('Creating isolated DNS user...');
  const dnsUser = await createRandomDNSUser();
  core.info(`Created isolated DNS user: ${dnsUser.username} (UID: ${dnsUser.uid})`);

  // Configure ipsets
  core.info('Configuring ipsets...');
  await setupIpsets();

  return dnsUser;
}

export async function createRandomDNSUser(): Promise<DnsUser> {
  // Generate random username with 16 hex characters
  const randomHex = crypto.randomBytes(8).toString('hex');
  const username = `dns-${randomHex}`;

  // Generate random UID in safe range (60000-65000 to avoid conflicts)
  const uid = 60000 + Math.floor(Math.random() * 5000);

  // Create system user with no login, no home directory
  await exec.exec('sudo', [
    'useradd',
    '--system',
    '--no-create-home',
    '--shell',
    '/usr/sbin/nologin',
    '--uid',
    uid.toString(),
    username
  ]);

  return { username, uid };
}

export async function setupIpsets() {
  // Create ipsets for allowlisting
  await exec.exec('sudo', [
    'ipset',
    'create',
    'github',
    'hash:ip',
    'family',
    'inet',
    'hashsize',
    '1024',
    'maxelem',
    '10000'
  ]);
  await exec.exec('sudo', [
    'ipset',
    'create',
    'user',
    'hash:ip',
    'family',
    'inet',
    'hashsize',
    '1024',
    'maxelem',
    '10000'
  ]);
}

export async function setupFirewallRules(dnsUid: number, logPrefix: string = ''): Promise<void> {
  // Flush OUTPUT chain
  await exec.exec('sudo', ['iptables', '-F', 'OUTPUT']);

  // Allow established connections on eth0
  await exec.exec('sudo', [
    'iptables',
    '-A',
    'OUTPUT',
    '-o',
    'eth0',
    '-m',
    'conntrack',
    '--ctstate',
    'ESTABLISHED',
    '-j',
    'ACCEPT'
  ]);

  // Allow Azure metadata service (required for GitHub Actions)
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-d', '168.63.129.16', '-j', 'ACCEPT']);
  await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-d', '169.254.169.254', '-j', 'ACCEPT']);

  // Log GitHub ipset matches
  await exec.exec('sudo', [
    'iptables',
    '-A',
    'OUTPUT',
    '-o',
    'eth0',
    '-m',
    'set',
    '--match-set',
    'github',
    'dst',
    '-j',
    'LOG',
    `--log-prefix=${logPrefix}GitHub-Allow: `
  ]);
  await exec.exec('sudo', [
    'iptables',
    '-A',
    'OUTPUT',
    '-o',
    'eth0',
    '-m',
    'set',
    '--match-set',
    'github',
    'dst',
    '-j',
    'ACCEPT'
  ]);

  // Log user-allowed ipset matches
  await exec.exec('sudo', [
    'iptables',
    '-A',
    'OUTPUT',
    '-o',
    'eth0',
    '-m',
    'set',
    '--match-set',
    'user',
    'dst',
    '-j',
    'LOG',
    `--log-prefix=${logPrefix}User-Allow: `
  ]);
  await exec.exec('sudo', [
    'iptables',
    '-A',
    'OUTPUT',
    '-o',
    'eth0',
    '-m',
    'set',
    '--match-set',
    'user',
    'dst',
    '-j',
    'ACCEPT'
  ]);

  // Allow DNS traffic to our upstream server - only from the random DNS user UID
  await exec.exec('sudo', [
    'iptables',
    '-A',
    'OUTPUT',
    '-o',
    'eth0',
    '-d',
    DEFAULT_DNS_SERVER,
    '-p',
    'udp',
    '--dport',
    '53',
    '-m',
    'owner',
    '--uid-owner',
    dnsUid.toString(),
    '-j',
    'ACCEPT'
  ]);
}

export async function setupDNSConfig(): Promise<void> {
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

export async function setupDNSMasq(
  mode: string,
  allowedDomains: string,
  blockRiskySubdomains: boolean,
  dnsUsername: string,
  logFile?: string
): Promise<string[]> {
  // Build DNS configuration using the config builder module
  const { config: dnsmasqConfig, blockedSubdomains } = buildDnsConfig({
    mode: mode as 'analyze' | 'enforce',
    allowedDomains,
    blockRiskySubdomains,
    dnsUsername,
    logFile
  });

  // Write configuration to file
  await exec.exec('sudo', ['tee', '/etc/dnsmasq.conf'], {
    input: Buffer.from(dnsmasqConfig)
  });

  // Restrict permissions - only root should read the DNS username
  await exec.exec('sudo', ['chmod', '600', '/etc/dnsmasq.conf']);
  await exec.exec('sudo', ['chown', 'root:root', '/etc/dnsmasq.conf']);

  return blockedSubdomains;
}

export async function restartServices(logFile?: string): Promise<void> {
  // Restart systemd-resolved and start dnsmasq
  await exec.exec('sudo', ['systemctl', 'restart', 'systemd-resolved']);
  await exec.exec('sudo', ['systemctl', 'restart', 'dnsmasq']);

  // After dnsmasq starts and creates log files, make them readable by all
  if (logFile) {
    // Wait a moment for dnsmasq to create the log file
    await new Promise(resolve => setTimeout(resolve, 500));

    // Make log file world-readable (dnsmasq creates it as 660)
    await exec.exec('sudo', ['chmod', '0644', logFile]);
  }
}

export async function finalizeFirewallRules(mode: string, logPrefix: string = ''): Promise<void> {
  if (mode === 'enforce') {
    // Log traffic that doesn't match any ipset (will be dropped)
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'LOG', `--log-prefix=Drop-Enforce: `]);

    // DEFAULT DENY: Drop external traffic not explicitly allowed (scoped to eth0)
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'DROP']);
  } else {
    // Analyze mode: Log traffic that doesn't match any ipset (but still allow it)
    await exec.exec('sudo', [
      'iptables',
      '-A',
      'OUTPUT',
      '-o',
      'eth0',
      '-j',
      'LOG',
      `--log-prefix=${logPrefix}Allow-Analyze: `
    ]);
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'ACCEPT']);
  }
}
