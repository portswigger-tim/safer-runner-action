/**
 * Runtime self-tests, run on every job right after the firewall is in place. They prove on
 * the live runner that (1) the SNI-level check actually fires (not just the Host check -
 * the P0 spike once had SNI enforcement silently off for a whole run) and (2) the proxy
 * repoints: it ignores the IP the client dialled and connects to the name instead.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import { FLOW_LOG, SELFTEST_BOGUS_IP, SELFTEST_HOST } from './constants';
import { FlowRecord, flowLogSize, ipOf, readFlowLog } from './flowlog';
import type { Mode } from './policy';

export interface SelfTestResult {
  name: string;
  ok: boolean;
  detail: string;
}

export const REPOINT_HOST = 'github.com';

async function curl(args: string[]): Promise<{ code: number; out: string }> {
  const r = await exec.getExecOutput('curl', ['-sS', '-m', '20', '-o', '/dev/null', '-w', '%{http_code}', ...args], {
    ignoreReturnCode: true,
    silent: true
  });
  return { code: r.exitCode, out: (r.stdout + r.stderr).trim() };
}

async function waitFor(from: number, pred: (r: FlowRecord) => boolean, ms = 5000): Promise<FlowRecord | null> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const hit = readFlowLog(FLOW_LOG, from).find(pred);
    if (hit) return hit;
    await new Promise(r => setTimeout(r, 200));
  }
  return null;
}

export async function sniBlockSelfTest(mode: Mode): Promise<SelfTestResult> {
  const from = flowLogSize(FLOW_LOG);
  const want = mode === 'enforce' ? 'BLOCK' : 'WOULD_BLOCK';
  const r = await curl(['--resolve', `${SELFTEST_HOST}:443:${SELFTEST_BOGUS_IP}`, `https://${SELFTEST_HOST}/`]);
  const rec = await waitFor(from, x => x.ev === 'tls' && x.sni === SELFTEST_HOST && x.layer === 'sni');
  const ok = rec !== null && rec.verdict === want && (mode === 'analyze' || r.code !== 0);
  return {
    name: 'sni-block',
    ok,
    detail: rec
      ? `SNI ${SELFTEST_HOST} -> ${rec.verdict} (${rec.reason}); curl exit ${r.code}`
      : `no SNI-layer record (curl: ${r.out})`
  };
}

export async function repointSelfTest(): Promise<SelfTestResult> {
  const from = flowLogSize(FLOW_LOG);
  const r = await curl(['--resolve', `${REPOINT_HOST}:443:${SELFTEST_BOGUS_IP}`, `https://${REPOINT_HOST}/robots.txt`]);
  const rec = await waitFor(
    from,
    x => (x.ev === 'https' || x.ev === 'http') && x.host === REPOINT_HOST && ipOf(x.dst) === SELFTEST_BOGUS_IP
  );
  const upstream = ipOf(rec?.upstream);
  const ok = r.out === '200' && rec !== null && upstream !== '' && upstream !== SELFTEST_BOGUS_IP;
  return {
    name: 'repoint',
    ok,
    detail: rec
      ? `client dialled ${SELFTEST_BOGUS_IP}, proxy connected to ${rec.upstream} (HTTP ${r.out})`
      : `no flow record for the repoint probe (curl: ${r.out})`
  };
}

export async function runSelfTests(mode: Mode): Promise<SelfTestResult[]> {
  const results = [await sniBlockSelfTest(mode), await repointSelfTest()];
  for (const t of results) {
    (t.ok ? core.info : core.warning)(`${t.ok ? '✅' : '❌'} self-test ${t.name}: ${t.detail}`);
  }
  return results;
}

/** Byte range of the flow log the self-tests wrote to (recorded in the root-owned setup marker). */
export type SelfTestWindow = [number, number];

/** The decision records the two probes above produce. */
export function isSelfTestRecord(r: FlowRecord): boolean {
  if (r.sni === SELFTEST_HOST || r.host === SELFTEST_HOST) return true;
  return ipOf(r.dst) === SELFTEST_BOGUS_IP && (r.sni === REPOINT_HOST || r.host === REPOINT_HOST);
}

/**
 * Flow records without the action's own self-test probes, so the report doesn't list them as
 * the job's traffic. Only records inside the self-test window (written before any job step
 * ran) are dropped - otherwise a step could hide traffic by dialling 192.0.2.1. Without a
 * window only the `.invalid` probe name is dropped: it never resolves and carries nothing.
 */
export function withoutSelfTests(records: FlowRecord[], offsets: number[], window?: SelfTestWindow): FlowRecord[] {
  return records.filter((r, i) => {
    if (!isSelfTestRecord(r)) return true;
    if (!window) return !(r.sni === SELFTEST_HOST || r.host === SELFTEST_HOST);
    return !(offsets[i] >= window[0] && offsets[i] < window[1]);
  });
}
