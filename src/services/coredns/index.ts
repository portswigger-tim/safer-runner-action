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
import { COREDNS_BIN, COREDNS_SHA256, COREDNS_SOURCES, DNS_LOG, DNS_UNIT } from '../../constants';
import { writeFiles } from '../../system/files';
import { realHost, sudo, type Host } from '../../system/host';
import { installPinnedBinary } from '../../system/install';
import type { Rendered } from '../../system/types';
import { startUnit } from '../../system/unit';
import { DNS_LISTEN, parseHostsNames, type LocalHosts } from './config';

export { render, type CoreDnsFacts } from './config';

export async function install(h: Host = realHost): Promise<void> {
  await installPinnedBinary(COREDNS_SOURCES, COREDNS_SHA256, 'coredns', COREDNS_BIN, 'coredns', h);
}

export interface DnsUser {
  username: string;
  uid: number;
}

/** The resolver's own system user: a random name and uid, no login, no home. */
export async function createUser(h: Host): Promise<DnsUser> {
  // Generate random username with 16 hex characters
  const randomHex = crypto.randomBytes(8).toString('hex');
  const username = `dns-${randomHex}`;

  // Generate random UID in safe range (60000-65000 to avoid conflicts)
  const uid = 60000 + Math.floor(Math.random() * 5000);

  await sudo(
    ['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', '--uid', uid.toString(), username],
    {},
    h
  );
  return { username, uid };
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

declare const dnsReady: unique symbol;
/** CoreDNS is up and answering. Minted only by start(). */
export type DnsReady = { readonly [dnsReady]: true };

declare const resolverOn: unique symbol;
/** The system resolver points at CoreDNS. Minted only by cutover(). */
export type ResolverOn = { readonly [resolverOn]: true };

/** Always allowlisted (GitHub core): CoreDNS is ready once it resolves this. */
export const READY_NAME = 'github.com';
const READY_TIMEOUT_MS = 20000;

/** (Re)start CoreDNS with its rendered files and wait until it answers. */
export async function start(h: Host, r: Rendered): Promise<DnsReady> {
  await writeFiles(h, r.inert);
  let last = '';
  await startUnit(h, r.unit, {
    ready: async () => (last = await probe(READY_NAME, 2000)) === 'ok',
    pollMs: 300,
    timeoutMs: READY_TIMEOUT_MS,
    diagnostics: [
      ['systemctl', 'status', DNS_UNIT, '--no-pager', '-l'],
      ['journalctl', '-u', DNS_UNIT, '--no-pager', '-n', '30'],
      ['tail', '-n', '30', DNS_LOG],
      ['ss', '-lntup', 'sport = :53']
    ],
    timeoutError: () =>
      new Error(`CoreDNS did not answer for ${READY_NAME} within ${READY_TIMEOUT_MS / 1000}s (last: ${last})`)
  });
  core.info(`✅ CoreDNS up on ${DNS_LISTEN}:53 (${READY_NAME} resolved)`);
  return Object.freeze({}) as DnsReady;
}

/**
 * Point the system resolver at CoreDNS: a systemd-resolved drop-in (no stub listener, CoreDNS as
 * its server), resolv.conf replaced, resolved restarted. Only once CoreDNS answers.
 */
export async function cutover(h: Host, _dns: DnsReady): Promise<ResolverOn> {
  await sudo(['mkdir', '-p', '/etc/systemd/resolved.conf.d'], {}, h);
  await sudo(
    ['tee', '/etc/systemd/resolved.conf.d/no-stub.conf'],
    {
      input: Buffer.from('[Resolve]\nDNS=127.0.0.1\nDNSSEC=yes\nDNSStubListener=no')
    },
    h
  );
  await sudo(['unlink', '/etc/resolv.conf'], {}, h);
  await sudo(['tee', '/etc/resolv.conf'], { input: Buffer.from('nameserver 127.0.0.1\n') }, h);
  await sudo(['systemctl', 'restart', 'systemd-resolved'], {}, h);
  return Object.freeze({}) as ResolverOn;
}
