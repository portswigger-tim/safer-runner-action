/**
 * DNS plumbing and logging helpers carried over from v1. The resolver itself (CoreDNS) lives
 * in src/dns.ts; this points the system at it (resolv.conf, systemd-resolved).
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as crypto from 'crypto';

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

/** Apply the resolved.conf drop-in written by setupDNSConfig (releases its stub listener). */
export async function restartResolved(): Promise<void> {
  await exec.exec('sudo', ['systemctl', 'restart', 'systemd-resolved']);
}
