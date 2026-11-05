/**
 * v2 resolver: CoreDNS on 127.0.0.1:53 (replaced dnsmasq). The firewall sends every :53
 * query on the host (and from containers) here; only the resolver's uid may reach the
 * upstream servers. enforce: allowlisted names (exact / *.x / glob, the proxy's own pattern
 * set) are forwarded, everything else - including subdomains of exact entries - gets
 * NXDOMAIN locally and never leaves the VM. See src/config/corefile-builder.ts.
 *
 * No DNS-rebind filtering: the proxy's upstream-IP guard (server_connect) refuses a strict
 * superset of internal answers and logs the address, and anything outside the proxy can
 * only reach addresses a step could dial by IP anyway (docs/spikes, REPLACE-vs-FRONT §3).
 */

import * as core from '@actions/core';
import * as dns from 'dns';
import * as exec from '@actions/exec';
import { COREDNS_BIN, COREDNS_SHA256, COREDNS_URL, COREFILE, DNS_LOG, DNS_UNIT, ETC_DIR } from './constants';
import { buildCorefile, DNS_LISTEN, type CorefileOptions } from './config/corefile-builder';
import { installPinnedBinary } from './proxy';

async function sudo(args: string[], opts: exec.ExecOptions = {}): Promise<number> {
  return exec.exec('sudo', args, opts);
}

export async function installCoreDns(): Promise<void> {
  await installPinnedBinary(COREDNS_URL, COREDNS_SHA256, 'coredns', COREDNS_BIN, 'coredns');
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
