/**
 * v2 proxy lifecycle: install the pinned mitmdump, create the proxy user, copy the addon and
 * write its config, then run mitmdump under systemd outside the runner's process tree.
 * The CA is ./ca.ts; distributing trust in it is ./trust.ts.
 */

import * as core from '@actions/core';
import * as fs from 'fs';
import * as net from 'net';
import * as path from 'path';
import {
  ADDON_DIR,
  ADDON_FILES,
  FLOW_LOG,
  MITMDUMP_BIN,
  MITMPROXY_SHA256,
  MITMPROXY_URL,
  PROXY_LISTEN_HOST,
  PROXY_UNIT,
  PROXY_USER
} from '../../constants';
import { writeFiles } from '../../system/files';
import { realHost, sudo, type Host } from '../../system/host';
import { installPinnedBinary } from '../../system/install';
import type { Rendered } from '../../system/types';
import { startUnit } from '../../system/unit';
import type { CaReady } from './ca';
import type { ProxyPorts } from './config';

export { mitmdumpArgs, render, type ProxyFacts, type ProxyPorts } from './config';

declare const configWritten: unique symbol;
/** The addon and the proxy's rendered files are in place. Minted only by writeConfig(). */
export type ProxyConfigWritten = { readonly [configWritten]: true };

declare const proxyReady: unique symbol;
/** mitmdump listens on both ports and the addon passed its own startup self-test. Minted only by start(). */
export type ProxyReady = { readonly [proxyReady]: true };

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
 * (the proxy binds them seconds later; start() fails loudly if something took one meanwhile).
 */
export async function allocateProxyPorts(
  probe: (port: number) => Promise<boolean> = canBind,
  random: () => number = Math.random
): Promise<ProxyPorts> {
  const [lo, hi] = PROXY_PORT_BAND;
  for (let i = 0; i < 50; i++) {
    const p = lo + Math.floor(random() * (hi - lo));
    if ((await probe(p)) && (await probe(p + 1))) return { port: p, containerPort: p + 1 };
  }
  throw new Error(`no free pair of loopback ports found in ${lo}-${hi + 1}`);
}

/** Download the pinned mitmproxy tarball, verify its sha256, install mitmdump root-owned. */
export async function install(h: Host = realHost): Promise<void> {
  await installPinnedBinary(MITMPROXY_URL, MITMPROXY_SHA256, 'mitmdump', MITMDUMP_BIN, 'mitmproxy', h);
}

/** Create the proxy system user (idempotent). Returns its uid. */
export async function ensureUser(h: Host): Promise<number> {
  const exists = await h.run('id', ['-u', PROXY_USER], { ignoreReturnCode: true, silent: true });
  if (exists !== 0) {
    await sudo(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', PROXY_USER], {}, h);
  }
  const { stdout } = await h.output('id', ['-u', PROXY_USER], { silent: true });
  return parseInt(stdout.trim(), 10);
}

/**
 * The addon, copied out of the (runner-writable) action checkout into a root-owned directory,
 * and the rendered files (policy.json, the flow log).
 */
export async function writeConfig(h: Host, r: Rendered): Promise<ProxyConfigWritten> {
  const src = path.join(actionRoot(), 'proxy');
  await sudo(['install', '-d', '-m', '0755', '-o', 'root', '-g', 'root', ADDON_DIR], {}, h);
  for (const f of ADDON_FILES) {
    await sudo(
      ['install', '-m', '0644', '-o', 'root', '-g', 'root', path.join(src, f), path.join(ADDON_DIR, f)],
      {},
      h
    );
  }
  await writeFiles(h, r.inert);
  return Object.freeze({}) as ProxyConfigWritten;
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

async function isListening(h: Host, port: number): Promise<boolean> {
  const { stdout } = await h.output('ss', ['-Hltn', `sport = :${port}`], { silent: true, ignoreReturnCode: true });
  return stdout.includes(`${PROXY_LISTEN_HOST}:${port}`);
}

const READY_TIMEOUT_MS = 90000;

/** Start the proxy unit and wait until it listens and the policy addon reported a good start. */
export async function start(
  h: Host,
  r: Rendered,
  ports: ProxyPorts,
  _config: ProxyConfigWritten,
  _ca: CaReady
): Promise<ProxyReady> {
  let started: StartRecord | null = null;
  await startUnit(h, r.unit, {
    ready: async () => {
      started = findStartRecord(fs.existsSync(FLOW_LOG) ? fs.readFileSync(FLOW_LOG, 'utf8') : '');
      return started !== null && (await isListening(h, ports.port)) && (await isListening(h, ports.containerPort));
    },
    pollMs: 500,
    timeoutMs: READY_TIMEOUT_MS,
    diagnostics: [
      ['systemctl', 'status', PROXY_UNIT, '--no-pager', '-l'],
      ['journalctl', '-u', PROXY_UNIT, '--no-pager', '-n', '50']
    ],
    timeoutError: () => new Error(`proxy did not become ready within ${READY_TIMEOUT_MS / 1000}s`)
  });
  const s = started as StartRecord | null;
  core.info(`✅ Proxy up (pid ${s?.pid}, ${s?.mode} policy loaded and self-tested)`);
  return Object.freeze({}) as ProxyReady;
}
