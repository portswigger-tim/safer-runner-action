/**
 * The post step's integrity check: read the baseline and the current state ONCE, compare them
 * once, and derive both the verdict (fail-on-tampering) and the job-summary details from that
 * one comparison, so the two can never disagree.
 */

import * as core from '@actions/core';
import { VALIDATION_STATE_FILE } from '../constants';
import type { Host } from '../system/host';
import { IPTABLES_CHAINS, chainListing, fileChecksum, sha256, type ValidationState } from './baseline';

export type IntegrityStatus = 'verified' | 'tampered' | 'unavailable';

/** What the report shows (report/render). */
export interface IntegrityDetails {
  status: IntegrityStatus;
  body: string;
}

export interface IntegrityResult {
  /** every file and chain matches the baseline (false when it is missing or unreadable) */
  intact: boolean;
  details: IntegrityDetails;
}

/** One checked file or chain. `current` null: deleted (file) or missing (chain). */
export interface Row {
  kind: 'file' | 'chain';
  name: string;
  baseline: string;
  current: string | null;
  /** reading it failed outright (not "missing": the read itself could not run) */
  error?: unknown;
}

/** The current state, as read by checkIntegrity: file -> checksum, chain -> checksum. */
export interface CurrentState {
  files: Map<string, string | null | { error: unknown }>;
  chains: Map<string, string>;
}

const NO_BASELINE: IntegrityDetails = { status: 'unavailable', body: 'No validation data available.\n\n' };

/** The baseline, or an error if it is not one. */
export function parseBaseline(raw: string): ValidationState {
  const state = JSON.parse(raw) as ValidationState;
  if (!Array.isArray(state?.files) || !Array.isArray(state?.iptablesRules)) {
    throw new Error('baseline has no files or iptablesRules list');
  }
  return state;
}

/** Compare (pure): one row per baselined file and chain, in baseline order. */
export function compare(state: ValidationState, current: CurrentState): Row[] {
  const files = state.files.map((f): Row => {
    const c = current.files.get(f.path);
    if (c !== null && typeof c === 'object')
      return { kind: 'file', name: f.path, baseline: f.checksum, current: null, error: c.error };
    return { kind: 'file', name: f.path, baseline: f.checksum, current: c ?? null };
  });
  const chains = state.iptablesRules.map((r): Row => ({
    kind: 'chain',
    name: r.chain,
    baseline: r.checksum,
    current: current.chains.get(r.chain) ?? null
  }));
  return [...files, ...chains];
}

const ok = (r: Row) => r.error === undefined && r.current === r.baseline;

/** The job-summary details (pure). */
export function renderDetails(state: ValidationState, rows: Row[], verifiedAt: string): IntegrityDetails {
  const line = (r: Row): string => {
    const b = r.baseline.substring(0, 16);
    let status: string;
    let shown: string;
    if (r.error !== undefined) [status, shown] = ['🚨 UNREADABLE', `${b} -> ERROR`];
    else if (r.current === null) [status, shown] = [r.kind === 'file' ? '🚨 DELETED' : '🚨 MISSING', `${b} -> MISSING`];
    else if (r.current === r.baseline) [status, shown] = ['VERIFIED', `${b} (unchanged)`];
    else [status, shown] = ['⚠️ TAMPERED', `${b} -> ${r.current.substring(0, 16)}`];
    return `| ${r.name} | ${status} | ${shown} |\n`;
  };
  let body = `**Baseline:** ${state.timestamp}\n`;
  body += `**Verified:** ${verifiedAt}\n\n`;
  body += '**Configuration Files**\n\n';
  body += '| File | Status | Checksum Comparison |\n';
  body += '|------|--------|--------------------|\n';
  body += rows
    .filter(r => r.kind === 'file')
    .map(line)
    .join('');
  body += '\n**Firewall Rules**\n\n';
  body += '| Chain | Status | Checksum Comparison |\n';
  body += '|-------|--------|--------------|\n';
  body += rows
    .filter(r => r.kind === 'chain')
    .map(line)
    .join('');
  body += '\n';
  return { status: rows.every(ok) ? 'verified' : 'tampered', body };
}

/** The job-log lines for each row. */
function logRow(r: Row): void {
  if (r.kind === 'file') {
    if (r.error !== undefined) core.error(`❌ Failed to verify ${r.name}: ${r.error}`);
    else if (r.current === null) core.error(`❌ Critical file ${r.name} was deleted after setup!`);
    else if (r.current === r.baseline) core.info(`✅ File ${r.name} integrity verified`);
    else core.error(`❌ File ${r.name} has been tampered with after setup!`);
  } else if (r.current === null) core.error(`❌ iptables chain ${r.name} is missing!`);
  else if (r.current === r.baseline) core.info(`✅ iptables chain ${r.name} integrity verified`);
  else core.error(`❌ iptables chain ${r.name} has been tampered with after setup!`);
}

/**
 * Read the baseline with the same privilege path as the checked files (an exact `sudo -n cat`
 * entry of the restricted sudoers). Null if it is missing or unreadable.
 */
async function readBaseline(h: Host): Promise<string | null> {
  const { exitCode, stdout } = await h.output('sudo', ['-n', 'cat', VALIDATION_STATE_FILE], {
    silent: true,
    ignoreReturnCode: true
  });
  return exitCode === 0 ? stdout : null;
}

/** Every baselined file, then every monitored chain, each read once. */
async function readCurrent(h: Host, state: ValidationState): Promise<CurrentState> {
  const files: CurrentState['files'] = new Map();
  for (const f of state.files) {
    try {
      files.set(f.path, await fileChecksum(h, f.path));
    } catch (error) {
      files.set(f.path, { error });
    }
  }
  const chains = new Map<string, string>();
  for (const chain of IPTABLES_CHAINS) {
    try {
      chains.set(chain, sha256(await chainListing(h, chain)));
    } catch (error) {
      core.warning(`⚠️  Failed to get current iptables ${chain} chain: ${error}`);
    }
  }
  return { files, chains };
}

/**
 * Compare the current state with the baseline. A missing or unreadable baseline is "not
 * intact" (unavailable / tampered in the summary).
 */
export async function checkIntegrity(h: Host): Promise<IntegrityResult> {
  core.info('🔍 Verifying system integrity against baseline...');

  const raw = await readBaseline(h);
  if (raw === null) {
    core.warning('⚠️  No baseline state file found - cannot verify integrity');
    return { intact: false, details: NO_BASELINE };
  }

  let state: ValidationState;
  try {
    state = parseBaseline(raw);
  } catch (error) {
    core.error(`❌ Failed to read baseline state: ${error}`);
    return { intact: false, details: { status: 'tampered', body: `Failed to generate report: ${error}\n` } };
  }

  const rows = compare(state, await readCurrent(h, state));
  rows.forEach(logRow);
  const intact = rows.every(ok);
  if (intact) core.info('✅ All validation checks passed - no tampering detected');
  return { intact, details: renderDetails(state, rows, new Date().toISOString()) };
}
