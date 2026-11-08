/**
 * The integrity baseline: SHA256 checksums of the security config files and iptables chains,
 * captured when setup is done and checked by the post step (./check.ts).
 *
 * 1. Setup completes -> captureBaseline() stores the checksums, root-owned 0600
 * 2. The job runs (potentially hostile code)
 * 3. Post step -> checkIntegrity() compares the current state with the baseline, once
 *
 * A tripwire, not tamper-proof: the post step runs as the runner user from files the job can
 * modify (docs/DESIGN-post-run-integrity.md).
 */

import * as core from '@actions/core';
import * as crypto from 'crypto';
import { VALIDATION_STATE_FILE } from '../constants';
import type { SudoLogging } from '../services/sudo';
import { sudo, type Host } from '../system/host';

export interface FileChecksum {
  path: string;
  checksum: string;
  timestamp: string;
}

export interface IptablesRuleChecksum {
  chain: string;
  rules: string;
  checksum: string;
  timestamp: string;
}

/** The stored baseline (VALIDATION_STATE_FILE). */
export interface ValidationState {
  files: FileChecksum[];
  iptablesRules: IptablesRuleChecksum[];
  timestamp: string;
}

/**
 * iptables chains to monitor for tampering: the built-in hooks plus the chains the v2
 * action owns. `table:CHAIN` selects a non-filter table.
 */
export const IPTABLES_CHAINS = [
  'INPUT',
  'OUTPUT',
  'FORWARD',
  'SAFER_RUNNER_OUT',
  'nat:OUTPUT',
  'nat:SAFER_RUNNER_NAT',
  // container egress (P2); absent when Docker isn't running (an absent chain lists as empty)
  'DOCKER-USER',
  'SAFER_RUNNER_CFWD',
  'nat:SAFER_RUNNER_CNAT'
] as const;

/** `iptables` arguments that list one chain spec (`CHAIN` or `table:CHAIN`). */
export function iptablesListArgs(spec: string): string[] {
  const [table, chain] = spec.includes(':') ? spec.split(':') : ['filter', spec];
  return [...(table === 'filter' ? [] : ['-t', table]), '-L', chain, '-n', '--line-numbers'];
}

/**
 * Security configuration files monitored for tampering
 * The sudo logging config file is appended at runtime (it depends on the sudo implementation)
 */
export const CRITICAL_FILES = [
  '/etc/safer-runner/Corefile',
  '/etc/resolv.conf',
  '/etc/systemd/resolved.conf.d/no-stub.conf',
  '/etc/safer-runner/policy.json',
  '/opt/safer-runner/proxy/policy.py',
  '/opt/safer-runner/proxy/policy_core.py'
] as const;

/** sudo commands that store the baseline (exact; also filtered from the sudo report). */
export const BASELINE_WRITE_COMMANDS: string[][] = [
  ['touch', VALIDATION_STATE_FILE],
  ['chown', 'root:root', VALIDATION_STATE_FILE],
  ['chmod', '0600', VALIDATION_STATE_FILE],
  ['tee', VALIDATION_STATE_FILE]
];

declare const baselineCaptured: unique symbol;
/**
 * The baseline is stored (root-owned 0600), with sudo logging already on. Minted only by
 * captureBaseline(); restricting sudo takes it, so it comes after.
 */
export type BaselineCaptured = { readonly [baselineCaptured]: true };

export function sha256(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * SHA256 of a file, read with `sudo cat` (root-only files too; the post step's reads are exact
 * entries of the restricted sudoers). Null if it cannot be read: missing.
 */
export async function fileChecksum(h: Host, filePath: string): Promise<string | null> {
  const { exitCode, stdout } = await h.output('sudo', ['cat', filePath], { silent: true, ignoreReturnCode: true });
  return exitCode === 0 ? sha256(stdout) : null;
}

/** The listing of one chain spec. A chain that does not exist lists as empty. */
export async function chainListing(h: Host, chain: string): Promise<string> {
  const { stdout } = await h.output('sudo', ['iptables', ...iptablesListArgs(chain)], {
    silent: true,
    ignoreReturnCode: true
  });
  return stdout;
}

/**
 * Capture the post-setup baseline once all configuration is complete. Every file must exist
 * (a missing one is a setup failure); chains are recorded as they list.
 */
export async function captureBaseline(h: Host, files: string[], _logging: SudoLogging): Promise<BaselineCaptured> {
  core.info('📋 Capturing post-setup security baseline...');

  const state: ValidationState = {
    files: [],
    iptablesRules: [],
    timestamp: new Date().toISOString()
  };

  for (const filePath of files) {
    try {
      const checksum = await fileChecksum(h, filePath);
      if (checksum) {
        state.files.push({ path: filePath, checksum, timestamp: new Date().toISOString() });
        core.info(`✅ Captured baseline checksum for ${filePath}: ${checksum.substring(0, 16)}...`);
      } else {
        core.error(`❌ Expected file ${filePath} not found after setup - this indicates a setup failure`);
        throw new Error(`Critical file ${filePath} missing after setup completion`);
      }
    } catch (error) {
      core.error(`❌ Failed to capture baseline for ${filePath}: ${error}`);
      throw error;
    }
  }

  for (const chain of IPTABLES_CHAINS) {
    try {
      const rules = await chainListing(h, chain);
      const checksum = sha256(rules);
      state.iptablesRules.push({ chain, rules, checksum, timestamp: new Date().toISOString() });
      core.info(`✅ Captured iptables ${chain} chain: ${checksum.substring(0, 16)}...`);
    } catch (error) {
      core.warning(`⚠️  Failed to capture iptables ${chain} chain: ${error}`);
    }
  }

  // Root-owned 0600 under /etc/safer-runner, never a runner-writable location: the runner could
  // otherwise rewrite it to match a tampered state (review M1). Mode and owner are set before
  // the content goes in; each command is in INTERNAL_SUDO_COMMANDS (sudo logging is on here).
  // A restricted file: a named step, never writeFiles.
  const json = JSON.stringify(state, null, 2);
  for (const args of BASELINE_WRITE_COMMANDS) {
    await sudo(args, args[0] === 'tee' ? { input: Buffer.from(json), silent: true } : {}, h);
  }
  core.info(`💾 Security baseline saved to ${VALIDATION_STATE_FILE}`);
  return Object.freeze({}) as BaselineCaptured;
}
