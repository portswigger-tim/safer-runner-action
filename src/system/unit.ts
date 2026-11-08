/**
 * Transient systemd units: outside the runner's process tree (the runner's orphan cleanup
 * would otherwise kill them before "Complete job"), restarted on any exit unless the unit says
 * otherwise, sandboxed.
 */

import { sleep, sudo, type Host } from './host';
import type { UnitSpec } from './types';

/** Sandboxing every unit gets; a service puts it among its own props. */
export const HARDENING = ['NoNewPrivileges=yes', 'PrivateTmp=yes', 'ProtectHome=yes', 'ProtectSystem=strict'];

export function transientUnitArgs(u: UnitSpec): string[] {
  return [
    'systemd-run',
    `--unit=${u.unit}`,
    `--description=${u.description}`,
    `--uid=${u.user}`,
    `--gid=${u.user}`,
    ...(u.restart === 'no' ? ['-p', 'Restart=no'] : ['-p', 'Restart=always', '-p', 'RestartSec=1']),
    ...u.props.flatMap(p => ['-p', p]),
    ...Object.entries(u.env ?? {}).map(([k, v]) => `--setenv=${k}=${v}`),
    ...u.argv
  ];
}

export interface Readiness {
  /** polled until true or the deadline */
  ready: () => Promise<boolean>;
  pollMs: number;
  timeoutMs: number;
  /** sudo commands whose output helps when the unit never came up (failures ignored) */
  diagnostics: string[][];
  timeoutError: () => Error;
}

/** (Re)start the unit and wait until it is ready; on a timeout, print diagnostics and throw. */
export async function startUnit(h: Host, u: UnitSpec, r: Readiness): Promise<void> {
  const quiet = { ignoreReturnCode: true, silent: true };
  await sudo(['systemctl', 'stop', u.unit], quiet, h);
  await sudo(['systemctl', 'reset-failed', u.unit], quiet, h);
  await sudo(transientUnitArgs(u), {}, h);

  const deadline = Date.now() + r.timeoutMs;
  while (Date.now() < deadline) {
    if (await r.ready()) return;
    await sleep(r.pollMs);
  }
  for (const d of r.diagnostics) await sudo(d, { ignoreReturnCode: true }, h);
  throw r.timeoutError();
}
