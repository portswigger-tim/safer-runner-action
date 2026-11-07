/**
 * Privileged-command helpers shared by the services (sudo, root-owned file writes, timing).
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';

export async function sudo(args: string[], opts: exec.ExecOptions = {}): Promise<number> {
  return exec.exec('sudo', args, opts);
}

export async function sudoWrite(file: string, content: string, mode: string, owner = 'root:root'): Promise<void> {
  await sudo(['tee', file], { input: Buffer.from(content), silent: true });
  await sudo(['chown', owner, file]);
  await sudo(['chmod', mode, file]);
}

export async function timed<T>(label: string, fn: () => Promise<T>): Promise<T> {
  const t0 = Date.now();
  try {
    return await fn();
  } finally {
    core.info(`⏱ ${label}: ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  }
}
