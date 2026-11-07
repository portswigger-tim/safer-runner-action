/**
 * A Host that records commands instead of running them, for unit tests of a service's effects.
 */

import type { Host } from './host';

export function recordingHost(exitCode: (line: string) => number = () => 0): { host: Host; calls: string[] } {
  const calls: string[] = [];
  const run = (cmd: string, args: string[]) => {
    const line = [cmd, ...args].join(' ');
    calls.push(line);
    return exitCode(line);
  };
  return {
    calls,
    host: {
      run: async (cmd, args) => run(cmd, args),
      output: async (cmd, args) => ({ exitCode: run(cmd, args), stdout: '', stderr: '' })
    }
  };
}
