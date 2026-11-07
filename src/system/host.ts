/**
 * The host port: every command the action runs on the runner goes through a Host, so a service's
 * effects can be driven by a fake in tests. Plus the privileged-command helpers built on it.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';

export interface Host {
  /** Run a command; its exit code (a non-zero exit throws unless `ignoreReturnCode`). */
  run(cmd: string, args: string[], opts?: exec.ExecOptions): Promise<number>;
  /** Run a command and capture its output. */
  output(cmd: string, args: string[], opts?: exec.ExecOptions): Promise<exec.ExecOutput>;
}

/** The runner itself. */
export const realHost: Host = {
  run: (cmd, args, opts) => exec.exec(cmd, args, opts),
  output: (cmd, args, opts) => exec.getExecOutput(cmd, args, opts)
};

export async function sudo(args: string[], opts: exec.ExecOptions = {}, h: Host = realHost): Promise<number> {
  return h.run('sudo', args, opts);
}

export async function timed<T>(label: string, fn: () => Promise<T>): Promise<T> {
  const t0 = Date.now();
  try {
    return await fn();
  } finally {
    core.info(`⏱ ${label}: ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}
