/**
 * Runtime self-tests, run on every job right after the firewall is in place. They prove on
 * the live runner that (1) the SNI-level check actually fires (not just the Host check -
 * the P0 spike once had SNI enforcement silently off for a whole run) and (2) the proxy
 * repoints: it ignores the IP the client dialled and connects to the name instead; and (3) the
 * resolver applies exact-FQDN semantics: a random subdomain of an exact entry is refused on
 * the runner (enforce) and labelled in the DNS log.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as crypto from 'crypto';
import * as fs from 'fs';
import { DNS_LOG, FLOW_LOG, SELFTEST_BOGUS_IP, SELFTEST_HOST } from '../constants';
import { FlowRecord, flowLogSize, ipOf, readFlowLog } from '../flowlog';
import { probe } from '../services/coredns';
import type { FirewallOn } from '../services/iptables';
import { parseDnsLog } from '../parsers/dns-parser';
import { compilePattern, matchesAny, type Mode } from '../policy';

export interface SelfTestResult {
  name: string;
  ok: boolean;
  detail: string;
}

/**
 * The repoint probe: a bodiless GET of this fixed public file. The addon recognises exactly this
 * request dialled at SELFTEST_BOGUS_IP (policy_core.is_selftest_probe) and exempts it from
 * http-filter, so a job's filter on this host cannot fail setup. Checked against
 * proxy/test-vectors.json "selftest_probe".
 */
export const REPOINT_HOST = 'github.com';
export const REPOINT_PATH = '/robots.txt';

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
  const r = await curl([
    '--resolve',
    `${REPOINT_HOST}:443:${SELFTEST_BOGUS_IP}`,
    `https://${REPOINT_HOST}${REPOINT_PATH}`
  ]);
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

/** Preferred parent for the DNS probe: exact in the GitHub list, under no wildcard. */
const DNS_PROBE_PARENT = 'objects.githubusercontent.com';

/**
 * A fresh name under an exact allowlist entry that no pattern allows - what a step would use to
 * tunnel data through an allowlisted zone. Null if every exact entry sits under a wildcard.
 */
export function dnsProbeName(allow: string[], rand = crypto.randomBytes(6).toString('hex')): string | null {
  const compiled = allow.map(compilePattern);
  const exact = allow.filter(p => !p.includes('*'));
  const parents = [...exact.filter(p => p === DNS_PROBE_PARENT), ...exact];
  for (const parent of parents) {
    const name = `srst-${rand}.${parent}`;
    if (!matchesAny(name, compiled)) return name;
  }
  return null;
}

export async function dnsExactSelfTest(mode: Mode, name: string | null): Promise<SelfTestResult> {
  if (!name) return { name: 'dns-exact', ok: true, detail: 'no exact allowlist entry to probe (skipped)' };
  const want = mode === 'enforce' ? 'BLOCK' : 'WOULD_BLOCK';
  const answer = await probe(name);
  let logged = false;
  for (let i = 0; i < 15 && !logged; i++) {
    const log = fs.existsSync(DNS_LOG) ? fs.readFileSync(DNS_LOG, 'utf8') : '';
    logged = parseDnsLog(log).some(q => q.name === name && q.verdict === want);
    if (!logged) await new Promise(r => setTimeout(r, 200));
  }
  const ok = logged && (mode === 'analyze' || answer === 'NXDOMAIN');
  return {
    name: 'dns-exact',
    ok,
    detail: `${name} -> ${answer}; DNS log ${logged ? `labels it ${want}` : `has no ${want} line`}`
  };
}

declare const selfTestsRun: unique symbol;
/** The live self-tests have run (their results decide whether setup goes on). Minted only by runSelfTests(). */
export type SelfTestsRun = { readonly [selfTestsRun]: true };

/** The live self-tests: they prove the firewall in place on this runner, so they need it first. */
export async function runSelfTests(
  mode: Mode,
  dnsName: string | null,
  _firewall: FirewallOn
): Promise<{ results: SelfTestResult[]; selfTests: SelfTestsRun }> {
  const results = [await sniBlockSelfTest(mode), await repointSelfTest(), await dnsExactSelfTest(mode, dnsName)];
  for (const t of results) {
    (t.ok ? core.info : core.warning)(`${t.ok ? '✅' : '❌'} self-test ${t.name}: ${t.detail}`);
  }
  return { results, selfTests: Object.freeze({}) as SelfTestsRun };
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
