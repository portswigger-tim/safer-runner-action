/**
 * DNS (dnsmasq) and logging helpers carried over from v1. In v2 DNS is a supporting layer:
 * the proxy is the egress control; dnsmasq resolves for it, logs, and (enforce) refuses to
 * resolve names outside the allowlist so DNS can't be used as a tunnel.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as crypto from 'crypto';
import { buildDnsConfig } from './config/dns-config-builder';

export interface DnsUser {
  username: string;
  uid: number;
}

/**
 * Create /var/log/safer-runner directory with proper permissions
 * This directory will contain all safer-runner log files (DNS, iptables, sudo)
 */
export async function createLogDirectory(): Promise<void> {
  const logDir = '/var/log/safer-runner';

  // Create directory
  await exec.exec('sudo', ['mkdir', '-p', logDir]);

  // Set ownership to syslog:adm (rsyslog runs as syslog, runner is in adm group)
  await exec.exec('sudo', ['chown', 'syslog:adm', logDir]);

  // Make directory readable by all (so runner can read logs without sudo)
  await exec.exec('sudo', ['chmod', '755', logDir]);
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

/**
 * Setup rsyslog to filter iptables logs to dedicated files
 * This allows reading logs without sudo and provides clean separation
 * between pre-hook and main action logs
 *
 * Creates separate config files for pre-hook and main action to avoid
 * overwriting each other's configurations
 */
export async function setupIptablesLogging(
  logFile: string,
  logPrefixes: string[],
  configSuffix: string = ''
): Promise<void> {
  // Build rsyslog configuration to filter iptables logs
  // Filter by programname=kernel to only capture actual iptables log messages
  // (not sudo commands that set up the logging rules)
  const prefixArray = "['" + logPrefixes.join("', '") + "']";

  const rsyslogConfig = `if $programname == 'kernel' and $msg contains ${prefixArray} then ${logFile}
`;

  // Use different config file names for pre-hook and main action
  const configFile = configSuffix
    ? `/etc/rsyslog.d/10-iptables-safer-runner-${configSuffix}.conf`
    : '/etc/rsyslog.d/10-iptables-safer-runner.conf';

  // Write rsyslog configuration
  await exec.exec('sudo', ['tee', configFile], {
    input: Buffer.from(rsyslogConfig)
  });

  // Create log file and set ownership to syslog user (rsyslog runs as syslog:adm)
  // This allows rsyslog to write to the file
  await exec.exec('sudo', ['touch', logFile]);
  await exec.exec('sudo', ['chown', 'syslog:adm', logFile]);
  await exec.exec('sudo', ['chmod', '644', logFile]);

  // Restart rsyslog to apply configuration
  await exec.exec('sudo', ['systemctl', 'restart', 'rsyslog']);
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
  logFile?: string,
  primaryDnsServer?: string,
  secondaryDnsServer?: string,
  githubDomains?: string[]
): Promise<string[]> {
  // Build DNS configuration using the config builder module
  const { config: dnsmasqConfig, blockedSubdomains } = buildDnsConfig({
    mode: mode as 'analyze' | 'enforce',
    allowedDomains,
    blockRiskySubdomains,
    dnsUsername,
    logFile,
    primaryDnsServer,
    secondaryDnsServer,
    githubDomains,
    ipsets: false
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

const DNSMASQ_START_ATTEMPTS = 2;

/**
 * (Re)start dnsmasq, retrying once if it fails
 *
 * dnsmasq occasionally fails to start on hosted runners right after systemd-resolved
 * restarts. On failure the unit journal and port 53 listeners are printed so the cause
 * is visible in the job log.
 */
export async function startDnsmasq(retryDelayMs: number = 2000): Promise<void> {
  for (let attempt = 1; attempt <= DNSMASQ_START_ATTEMPTS; attempt++) {
    const exitCode = await exec.exec('sudo', ['systemctl', 'restart', 'dnsmasq'], { ignoreReturnCode: true });
    if (exitCode === 0) {
      return;
    }

    core.warning(`dnsmasq failed to start (attempt ${attempt}/${DNSMASQ_START_ATTEMPTS})`);
    await exec.exec('sudo', ['journalctl', '-xeu', 'dnsmasq', '--no-pager', '-n', '30'], { ignoreReturnCode: true });
    await exec.exec('sudo', ['ss', '-lntup', 'sport = :53'], { ignoreReturnCode: true });

    if (attempt < DNSMASQ_START_ATTEMPTS) {
      await exec.exec('sudo', ['systemctl', 'reset-failed', 'dnsmasq'], { ignoreReturnCode: true });
      await new Promise(resolve => setTimeout(resolve, retryDelayMs));
    }
  }

  throw new Error('dnsmasq failed to start - see the journal output above');
}

export async function restartServices(logFile?: string): Promise<void> {
  // Restart systemd-resolved and start dnsmasq
  await exec.exec('sudo', ['systemctl', 'restart', 'systemd-resolved']);
  await startDnsmasq();

  // After dnsmasq starts and creates log files, make them readable by all
  if (logFile) {
    // Wait a moment for dnsmasq to create the log file
    await new Promise(resolve => setTimeout(resolve, 500));

    // Make log file world-readable (dnsmasq creates it as 660)
    await exec.exec('sudo', ['chmod', '0644', logFile]);
  }
}
