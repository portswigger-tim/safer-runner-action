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
 * Logs to specified file for visibility and auditability
 *
 * @param logFile - Path to sudo log file (e.g., /tmp/pre-sudo.log or /tmp/main-sudo.log)
 */
export async function setupSudoLogging(logFile: string): Promise<void> {
  core.info(`Configuring sudo logging to ${logFile}...`);

  // Create a sudoers.d file to enable logging
  const logConfig = `Defaults logfile=${logFile}\n`;

  await exec.exec('sudo', ['tee', '/etc/sudoers.d/00-sudo-logging'], {
    input: Buffer.from(logConfig)
  });

  // Set appropriate permissions (must be 0440 or 0400 for sudoers files)
  await exec.exec('sudo', ['chmod', '0440', '/etc/sudoers.d/00-sudo-logging']);
  await exec.exec('sudo', ['chown', 'root:root', '/etc/sudoers.d/00-sudo-logging']);

  // Create the log file and make it readable by the runner
  await exec.exec('sudo', ['touch', logFile]);
  await exec.exec('sudo', ['chmod', '0644', logFile]);

  core.info(`✅ Sudo logging configured to ${logFile}`);
}

/**
 * Generate required sudo commands for validation and log parsing
 * These commands are needed by the post-action to:
 * - Read protected configuration files for integrity validation
 * - Query iptables rules for firewall validation
 * - Parse DNS and network logs for reporting
 *
 * @param username - The username to generate rules for (default: 'runner')
 * @returns Sudoers configuration string with required commands
 */
function getRequiredSudoCommands(username: string): string {
  return `
# Required commands for post-action validation and reporting
# These are automatically added by safer-runner-action

# Allow reading configuration files for checksum validation
${username} ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/dnsmasq.conf
${username} ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/resolv.conf
${username} ALL=(ALL) NOPASSWD: /usr/bin/cat /etc/systemd/resolved.conf.d/no-stub.conf

# Allow reading iptables rules for integrity validation
${username} ALL=(ALL) NOPASSWD: /usr/sbin/iptables -L * -n --line-numbers

# Allow parsing DNS and network logs for post-action reporting
${username} ALL=(ALL) NOPASSWD: /usr/bin/grep -E * /var/log/syslog
${username} ALL=(ALL) NOPASSWD: /usr/bin/grep -E * /tmp/*
`;
}

/**
 * Apply custom sudoers configuration for the runner user
 * This replaces the default unrestricted sudo access with user-specified rules
 *
 * The custom config is automatically appended with required commands for:
 * - Post-action integrity validation (reading config files, iptables rules)
 * - Log parsing (grep for DNS and network logs)
 *
 * @param sudoConfig - The custom sudoers configuration (multi-line string)
 */
export async function applyCustomSudoConfig(sudoConfig: string): Promise<void> {
  // Get the current user (should be 'runner' on GitHub Actions)
  let currentUser = '';
  await exec.exec('whoami', [], {
    listeners: {
      stdout: (data: Buffer) => {
        currentUser += data.toString().trim();
      }
    }
  });

  core.info(`Applying custom sudo configuration for user: ${currentUser}`);

  // Validate the sudo config using visudo
  const sudoersFile = `/etc/sudoers.d/${currentUser}`;
  const tempFile = `/tmp/${currentUser}-sudoers.tmp`;

  // Append required commands for validation and log parsing
  const requiredCommands = getRequiredSudoCommands(currentUser);
  const fullConfig = sudoConfig + '\n' + requiredCommands;

  try {
    // Write custom config + required commands to temp file
    await exec.exec('sudo', ['tee', tempFile], {
      input: Buffer.from(fullConfig + '\n')
    });

    // Validate with visudo
    await exec.exec('sudo', ['visudo', '-c', '-f', tempFile]);

    // If validation passes, set permissions before moving
    await exec.exec('sudo', ['chmod', '0440', tempFile]);
    await exec.exec('sudo', ['chown', 'root:root', tempFile]);
    await exec.exec('sudo', ['mv', tempFile, sudoersFile]);

    core.info(`✅ Custom sudo configuration applied to ${sudoersFile}`);
    core.info('🔒 Runner user now has restricted sudo access');
    core.info('ℹ️  Required validation and log parsing commands automatically added');
  } catch (error) {
    core.error(`Failed to apply custom sudo config: ${error}`);
    core.error('Invalid sudoers syntax. Please check your sudo-config input.');
    // Clean up temp file
    await exec.exec('sudo', ['rm', '-f', tempFile], { ignoreReturnCode: true });
    throw new Error('Invalid sudoers configuration');
  }
}

/**
 * Disable sudo access for the runner user
 * This prevents malicious code from using sudo to bypass security controls
 *
 * However, we still need to allow specific commands for post-action operations:
 * - sudo cat <file> - to read protected configuration files for integrity checks
 * - sudo iptables -L <chain> -n --line-numbers - to verify firewall rules
 * - sudo grep -E <pattern> <file> - to parse DNS and network logs for reporting
 *
 * The runner user on GitHub Actions has sudo access via /etc/sudoers.d/runner
 * which contains: runner ALL=(ALL) NOPASSWD:ALL
 *
 * We replace this with a minimal configuration that only allows validation commands.
 */
export async function disableSudoForRunner(): Promise<void> {
  core.info('Restricting sudo access to validation commands only');

  // Use applyCustomSudoConfig with an empty config to get just the required commands
  const validationOnlyHeader = `# Safer Runner Action - Validation-only sudo access
# This configuration allows only the commands needed for post-action integrity validation
# and log parsing. All other sudo commands will be denied.
`;

  await applyCustomSudoConfig(validationOnlyHeader);

  core.info('🔒 Runner user can only execute commands needed for integrity validation');
}

/**
 * Perform initial system setup: install dependencies, create DNS user, setup ipsets
 * Note: Sudo logging is NOT configured here - it's set up at the end of pre/main actions
 * to avoid capturing setup commands
 * Returns the created DNS user
 */
export async function performInitialSetup(): Promise<DnsUser> {
  // Install dependencies
  core.info('Installing dependencies...');
  await exec.exec('sudo', ['apt-get', 'update', '-qq']);
  await exec.exec('sudo', ['apt-get', 'install', '-y', 'dnsmasq', 'ipset']);

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
