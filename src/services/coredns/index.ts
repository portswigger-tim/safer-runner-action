/**
 * v2 resolver: CoreDNS on 127.0.0.1:53 (replaced dnsmasq). The firewall sends every :53
 * query on the host (and from containers) here; only the resolver's uid may reach the
 * upstream servers. enforce: allowlisted names (exact / *.x / glob, the proxy's own pattern
 * set) are forwarded, everything else - including subdomains of exact entries - gets
 * NXDOMAIN locally and never leaves the VM. See ./config.ts.
 *
 * No DNS-rebind filtering: the proxy's upstream-IP guard (server_connect) refuses a strict
 * superset of internal answers and logs the address, and anything outside the proxy can
 * only reach addresses a step could dial by IP anyway. See docs/DNS-COREDNS.md.
 */

import * as core from '@actions/core';
import * as crypto from 'crypto';
import * as dns from 'dns';
import * as fs from 'fs';
import * as os from 'os';
import * as exec from '@actions/exec';
import { COREDNS_BIN, COREDNS_SHA256, COREDNS_URL, COREFILE, DNS_LOG, DNS_UNIT, ETC_DIR } from '../../constants';
import { buildCorefile, DNS_LISTEN, parseHostsNames, type CorefileOptions, type LocalHosts } from './config';
import { sudo } from '../../system/host';
import { installPinnedBinary } from '../../system/install';

export async function installCoreDns(): Promise<void> {
  await installPinnedBinary(COREDNS_URL, COREDNS_SHA256, 'coredns', COREDNS_BIN, 'coredns');
}

export const HOSTS_FILE = '/etc/hosts';
/** Debian's address for the machine's own name when it has no other (`127.0.1.1 <hostname>`). */
const OWN_NAME_FALLBACK = '127.0.1.1';

/**
 * /etc/hosts names, plus the VM's hostname if /etc/hosts lacks it (AWS-hosted runners: it
 * resolved through the VPC resolver, and without it every sudo warns "unable to resolve
 * host"). Call BEFORE resolv.conf points at us, so the hostname resolves the original way.
 */
export async function localHosts(): Promise<LocalHosts> {
  let names: string[] = [];
  try {
    names = parseHostsNames(fs.readFileSync(HOSTS_FILE, 'utf8'));
  } catch {
    // no /etc/hosts: nothing to serve
  }
  const inline: LocalHosts['inline'] = [];
  const own = os.hostname().toLowerCase();
  if (own && !names.includes(own) && /^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$/.test(own)) {
    let addrs: string[] = [];
    try {
      addrs = (await dns.promises.lookup(own, { all: true })).map(a => a.address);
    } catch {
      // unresolvable before we started too
    }
    for (const ip of addrs.length ? addrs : [OWN_NAME_FALLBACK]) inline.push({ ip, name: own });
    core.info(
      `hostname ${own} is not in ${HOSTS_FILE}: the resolver answers it with ${inline.map(e => e.ip).join(', ')}`
    );
  }
  return { file: HOSTS_FILE, names, inline };
}

export async function writeCorefile(o: CorefileOptions): Promise<void> {
  const corefile = buildCorefile(o);
  await sudo(['install', '-d', '-m', '0755', '-o', 'root', '-g', 'root', ETC_DIR]);
  await sudo(['tee', COREFILE], { input: Buffer.from(corefile), silent: true });
  await sudo(['chown', 'root:root', COREFILE]);
  await sudo(['chmod', '0644', COREFILE]);
}

/**
 * systemd-run: outside the runner's process tree (its orphan cleanup would kill it), restarted
 * on any exit, as the random DNS user with only CAP_NET_BIND_SERVICE (for :53). stdout - the
 * `log` plugin - is appended by systemd to the world-readable DNS log the report reads.
 */
export function dnsSystemdRunArgs(dnsUser: string): string[] {
  return [
    'systemd-run',
    `--unit=${DNS_UNIT}`,
    '--description=safer-runner DNS resolver (CoreDNS)',
    `--uid=${dnsUser}`,
    `--gid=${dnsUser}`,
    '-p',
    'Restart=always',
    '-p',
    'RestartSec=1',
    '-p',
    'AmbientCapabilities=CAP_NET_BIND_SERVICE',
    '-p',
    'CapabilityBoundingSet=CAP_NET_BIND_SERVICE',
    '-p',
    'NoNewPrivileges=yes',
    '-p',
    'PrivateTmp=yes',
    '-p',
    'ProtectHome=yes',
    '-p',
    'ProtectSystem=strict',
    '-p',
    `StandardOutput=append:${DNS_LOG}`,
    '-p',
    `StandardError=append:${DNS_LOG}`,
    COREDNS_BIN,
    '-conf',
    COREFILE
  ];
}

export async function dumpDnsDiagnostics(): Promise<void> {
  const opts = { ignoreReturnCode: true };
  await sudo(['systemctl', 'status', DNS_UNIT, '--no-pager', '-l'], opts);
  await sudo(['journalctl', '-u', DNS_UNIT, '--no-pager', '-n', '30'], opts);
  await sudo(['tail', '-n', '30', DNS_LOG], opts);
  await sudo(['ss', '-lntup', 'sport = :53'], opts);
}

/** Resolve `name` (A) against our resolver. Returns 'ok', 'NXDOMAIN' or the error code. */
export async function probe(name: string, timeoutMs = 3000): Promise<string> {
  const r = new dns.promises.Resolver({ timeout: timeoutMs, tries: 1 });
  r.setServers([DNS_LISTEN]);
  try {
    await r.resolve4(name);
    return 'ok';
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? String(e);
    return code === dns.NOTFOUND ? 'NXDOMAIN' : code;
  }
}

/**
 * (Re)start CoreDNS and wait until it answers. The log file is pre-created 0644 root-owned:
 * systemd opens it as root and appends, so the mode sticks and the runner can read it.
 */
export async function startCoreDns(dnsUser: string, readinessName: string, timeoutMs = 20000): Promise<void> {
  await sudo(['touch', DNS_LOG]);
  await sudo(['chown', 'root:root', DNS_LOG]);
  await sudo(['chmod', '0644', DNS_LOG]);
  await sudo(['systemctl', 'stop', DNS_UNIT], { ignoreReturnCode: true, silent: true });
  await sudo(['systemctl', 'reset-failed', DNS_UNIT], { ignoreReturnCode: true, silent: true });
  await sudo(dnsSystemdRunArgs(dnsUser));

  const deadline = Date.now() + timeoutMs;
  let last = '';
  while (Date.now() < deadline) {
    last = await probe(readinessName, 2000);
    if (last === 'ok') {
      core.info(`✅ CoreDNS up on ${DNS_LISTEN}:53 (${readinessName} resolved)`);
      return;
    }
    await new Promise(r => setTimeout(r, 300));
  }
  await dumpDnsDiagnostics();
  throw new Error(`CoreDNS did not answer for ${readinessName} within ${timeoutMs / 1000}s (last: ${last})`);
}

export interface DnsUser {
  username: string;
  uid: number;
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
