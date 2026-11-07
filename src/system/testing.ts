/**
 * A Host that records commands instead of running them, for unit tests of a service's effects.
 * Each call is `cmd args...`, with ` [ignore-rc]` / ` [silent]` when run with those options (a
 * command whose failure is ignored must show it), the same notation as src/orchestration.test.ts.
 */

import type { ExecOptions } from '@actions/exec';
import type { Host } from './host';

export function recordingHost(exitCode: (line: string) => number = () => 0): { host: Host; calls: string[] } {
  const calls: string[] = [];
  const run = (cmd: string, args: string[], opts: ExecOptions = {}) => {
    const line = [cmd, ...args].join(' ');
    calls.push(`${line}${opts.ignoreReturnCode ? ' [ignore-rc]' : ''}${opts.silent ? ' [silent]' : ''}`);
    const code = exitCode(line);
    if (code !== 0 && !opts.ignoreReturnCode) throw new Error(`The process '${cmd}' failed with exit code ${code}`);
    return code;
  };
  return {
    calls,
    host: {
      run: async (cmd, args, opts) => run(cmd, args, opts),
      output: async (cmd, args, opts) => ({ exitCode: run(cmd, args, opts), stdout: '', stderr: '' })
    }
  };
}
