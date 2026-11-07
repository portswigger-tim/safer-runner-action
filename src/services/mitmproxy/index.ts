/**
 * v2 proxy lifecycle: install the pinned mitmdump, create the proxy user and its ephemeral
 * CA, write the policy, and run mitmdump under systemd outside the runner's process tree.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import * as net from 'net';
import * as path from 'path';
import {
  ADDON_DIR,
  ADDON_FILES,
  CA_CERT_FILE,
  ETC_DIR,
  FLOW_LOG,
  MITMDUMP_BIN,
  MITMPROXY_SHA256,
  MITMPROXY_URL,
  POLICY_FILE,
  PROXY_CA_KEY_FILE,
  PROXY_CONF_DIR,
  PROXY_LISTEN_HOST,
  PROXY_STREAM_LARGE_BODIES,
  PROXY_UNIT,
  PROXY_USER,
  TEARDOWN_BIN
} from '../../constants';
import { sudoWrite } from '../../system/files';
import { sudo, timed } from '../../system/host';
import { installPinnedBinary } from '../../system/install';
import type { PolicyConfig } from '../../policy';

export interface ProxyOptions {
  /** host listener (nat OUTPUT REDIRECT) */
  port: number;
  /** container listener (nat PREROUTING DNAT from the docker bridges); the addon classifies by it */
  containerPort: number;
}

/**
 * Root of the checked-out action (where proxy/policy.py lives). Derived from the running
 * script (<action>/dist/<entry>/index.js) rather than __dirname so the bundler can't
 * rewrite or relocate it.
 */
export function actionRoot(): string {
  const script = process.argv[1] || '';
  return path.resolve(path.dirname(script), '..', '..');
}

/**
 * Free-port band for the proxy listeners: above the registered ports dev servers favour
 * (3000, 5000, 8080, 9000...) and below Linux's ephemeral range (32768-60999), so an outgoing
 * connection's local port can never be the one we picked.
 */
export const PROXY_PORT_BAND: [number, number] = [20000, 32766];

function canBind(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const srv = net.createServer();
    srv.once('error', () => resolve(false));
    srv.listen({ host: PROXY_LISTEN_HOST, port, exclusive: true }, () => srv.close(() => resolve(true)));
  });
}

/**
 * Pick the proxy's two listener ports: host = P, container = P + 1, a random pair in
 * PROXY_PORT_BAND where both are free right now
 * (the proxy binds them seconds later; startProxy fails loudly if something took one meanwhile).
 */
export async function allocateProxyPorts(
  probe: (port: number) => Promise<boolean> = canBind,
  random: () => number = Math.random
): Promise<{ port: number; containerPort: number }> {
  const [lo, hi] = PROXY_PORT_BAND;
  for (let i = 0; i < 50; i++) {
    const p = lo + Math.floor(random() * (hi - lo));
    if ((await probe(p)) && (await probe(p + 1))) return { port: p, containerPort: p + 1 };
  }
  throw new Error(`no free pair of loopback ports found in ${lo}-${hi + 1}`);
}

/** Download the pinned mitmproxy tarball, verify its sha256, install mitmdump root-owned. */
export async function installMitmproxy(): Promise<void> {
  await installPinnedBinary(MITMPROXY_URL, MITMPROXY_SHA256, 'mitmdump', MITMDUMP_BIN, 'mitmproxy');
}

/** Create the proxy system user (idempotent). Returns its uid. */
export async function createProxyUser(): Promise<number> {
  const exists = await exec.exec('id', ['-u', PROXY_USER], { ignoreReturnCode: true, silent: true });
  if (exists !== 0) {
    await sudo(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', PROXY_USER]);
  }
  const { stdout } = await exec.getExecOutput('id', ['-u', PROXY_USER], { silent: true });
  return parseInt(stdout.trim(), 10);
}

/** Copy the addon out of the (runner-writable) action checkout into a root-owned directory. */
export async function installAddon(): Promise<void> {
  const src = path.join(actionRoot(), 'proxy');
  await sudo(['install', '-d', '-m', '0755', '-o', 'root', '-g', 'root', ADDON_DIR]);
  for (const f of ADDON_FILES) {
    await sudo(['install', '-m', '0644', '-o', 'root', '-g', 'root', path.join(src, f), path.join(ADDON_DIR, f)]);
  }
}

export async function writePolicy(config: PolicyConfig): Promise<void> {
  await sudo(['install', '-d', '-m', '0755', '-o', 'root', '-g', 'root', ETC_DIR]);
  await sudoWrite(POLICY_FILE, JSON.stringify(config, null, 2) + '\n', '0644');
  // The flow log is written by the proxy user and read (without sudo) by the post step.
  await sudo(['touch', FLOW_LOG]);
  await sudo(['chown', `${PROXY_USER}:${PROXY_USER}`, FLOW_LOG]);
  await sudo(['chmod', '0644', FLOW_LOG]);
}

/**
 * Generate the per-run CA: RSA-2048 (broadest client compatibility), 3-day validity, key
 * only ever on tmpfs, 0600, owned by the proxy user. mitmproxy mints leaf certs from it.
 * Publishes the public certificate to CA_CERT_FILE.
 */
export async function generateCa(): Promise<void> {
  await sudo(['install', '-d', '-m', '0755', '-o', 'root', '-g', 'root', path.dirname(PROXY_CONF_DIR)]);
  await sudo(['install', '-d', '-m', '0700', '-o', PROXY_USER, '-g', PROXY_USER, PROXY_CONF_DIR]);
  const key = `${PROXY_CONF_DIR}/ca-key.pem`;
  const cert = `${PROXY_CONF_DIR}/ca-cert.pem`;
  const subject = `/O=safer-runner/CN=safer-runner ephemeral CA ${process.env.GITHUB_RUN_ID || ''}`.trim();
  await sudo([
    '-u',
    PROXY_USER,
    'sh',
    '-c',
    'umask 077 && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3 ' +
      `-keyout "$1" -out "$2" -subj "$3" ` +
      '-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign ' +
      `&& cat "$1" "$2" > "$4" && rm -f "$1"`,
    'sh',
    key,
    cert,
    subject,
    PROXY_CA_KEY_FILE
  ]);
  // mitmproxy looks for <confdir>/mitmproxy-ca.pem (key + cert)
  await sudo(['install', '-m', '0644', '-o', 'root', '-g', 'root', cert, CA_CERT_FILE]);
}

/**
 * Root-owned teardown helper. The only privileged command the post step needs, so with
 * disable-sudo it is the single extra sudoers entry (exact path, no arguments).
 * Deleting the key on disk is all it does: the running proxy keeps the CA in memory so the
 * runner can still finish the job through it; the VM is destroyed afterwards.
 */
export async function installTeardownHelper(): Promise<void> {
  const script = `#!/bin/sh
# safer-runner: destroy the ephemeral CA private key (written by the action, root-owned).
rm -f ${PROXY_CA_KEY_FILE} ${PROXY_CONF_DIR}/ca-key.pem ${PROXY_CONF_DIR}/mitmproxy-ca.p12
`;
  await sudoWrite(TEARDOWN_BIN, script, '0755');
}

export function mitmdumpArgs(o: ProxyOptions): string[] {
  return [
    MITMDUMP_BIN,
    // two transparent listeners: a connection's listener tells host from container traffic
    '--mode',
    `transparent@${PROXY_LISTEN_HOST}:${o.port}`,
    '--mode',
    `transparent@${PROXY_LISTEN_HOST}:${o.containerPort}`,
    '--set',
    `confdir=${PROXY_CONF_DIR}`,
    '--set',
    'connection_strategy=lazy',
    '--set',
    `stream_large_bodies=${PROXY_STREAM_LARGE_BODIES}`,
    '--set',
    'block_global=false',
    '--set',
    'flow_detail=0',
    '--set',
    'termlog_verbosity=warn',
    '-s',
    `${ADDON_DIR}/policy.py`
  ];
}

/**
 * systemd-run: a transient service OUTSIDE the runner's process tree (the runner's orphan
 * cleanup would otherwise kill it before "Complete job", which itself goes through the
 * proxy), restarted on any exit, sandboxed to what it needs.
 */
export function systemdRunArgs(o: ProxyOptions): string[] {
  return [
    'systemd-run',
    `--unit=${PROXY_UNIT}`,
    '--description=safer-runner egress proxy',
    `--uid=${PROXY_USER}`,
    `--gid=${PROXY_USER}`,
    '-p',
    'Restart=always',
    '-p',
    'RestartSec=1',
    '-p',
    'UMask=0077',
    '-p',
    'NoNewPrivileges=yes',
    '-p',
    'PrivateTmp=yes',
    '-p',
    'ProtectHome=yes',
    '-p',
    'ProtectSystem=strict',
    '-p',
    `ReadWritePaths=${PROXY_CONF_DIR} ${FLOW_LOG}`,
    '-p',
    'LimitNOFILE=65536',
    `--setenv=HOME=${PROXY_CONF_DIR}`,
    `--setenv=SAFER_RUNNER_POLICY=${POLICY_FILE}`,
    ...mitmdumpArgs(o)
  ];
}

interface StartRecord {
  ev: string;
  ok?: boolean;
  pid?: number;
  mode?: string;
}

/** Find the addon's startup record (written only after its own self-test passed). */
export function findStartRecord(flowLog: string): StartRecord | null {
  let found: StartRecord | null = null;
  for (const line of flowLog.split('\n')) {
    if (!line.includes('"ev": "start"')) continue;
    try {
      const rec = JSON.parse(line) as StartRecord;
      if (rec.ev === 'start' && rec.ok === true) found = rec;
    } catch {
      // partial line
    }
  }
  return found;
}

async function isListening(port: number): Promise<boolean> {
  const { stdout } = await exec.getExecOutput('ss', ['-Hltn', `sport = :${port}`], {
    silent: true,
    ignoreReturnCode: true
  });
  return stdout.includes(`${PROXY_LISTEN_HOST}:${port}`);
}

export async function dumpProxyDiagnostics(): Promise<void> {
  const opts = { ignoreReturnCode: true };
  await sudo(['systemctl', 'status', PROXY_UNIT, '--no-pager', '-l'], opts);
  await sudo(['journalctl', '-u', PROXY_UNIT, '--no-pager', '-n', '50'], opts);
}

/** Start the proxy unit and wait until it listens and the policy addon reported a good start. */
export async function startProxy(o: ProxyOptions, timeoutMs = 90000): Promise<void> {
  await sudo(['systemctl', 'stop', PROXY_UNIT], { ignoreReturnCode: true, silent: true });
  await sudo(['systemctl', 'reset-failed', PROXY_UNIT], { ignoreReturnCode: true, silent: true });
  await sudo(systemdRunArgs(o));

  const deadline = Date.now() + timeoutMs;
  await timed('proxy start', async () => {
    while (Date.now() < deadline) {
      const log = fs.existsSync(FLOW_LOG) ? fs.readFileSync(FLOW_LOG, 'utf8') : '';
      const start = findStartRecord(log);
      if (start && (await isListening(o.port)) && (await isListening(o.containerPort))) {
        core.info(`✅ Proxy up (pid ${start.pid}, ${start.mode} policy loaded and self-tested)`);
        return;
      }
      await new Promise(r => setTimeout(r, 500));
    }
    await dumpProxyDiagnostics();
    throw new Error(`proxy did not become ready within ${timeoutMs / 1000}s`);
  });
}
