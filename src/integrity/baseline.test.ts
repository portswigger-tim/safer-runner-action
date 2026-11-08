import * as crypto from 'crypto';
import { VALIDATION_STATE_FILE } from '../constants';
import { INTERNAL_SUDO_COMMANDS, type SudoLogging } from '../services/sudo';
import type { Host } from '../system/host';
import {
  BASELINE_WRITE_COMMANDS,
  CRITICAL_FILES,
  IPTABLES_CHAINS,
  captureBaseline,
  iptablesListArgs
} from './baseline';
import { checkIntegrity, compare, parseBaseline, renderDetails } from './check';

jest.mock('@actions/core');

/** sudo logging's token (a test stands in for setupSudoLogging) */
const LOGGING = Object.freeze({}) as SudoLogging;
const FILES = ['/etc/safer-runner/Corefile', '/etc/resolv.conf'];
const sha = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

/**
 * A runner with files (read with `sudo cat`) and iptables chains (listed with `sudo iptables`).
 * A file's content may be a function: it is called on every read.
 */
function runner(files: Record<string, string | (() => string)>, chains: Record<string, string> = {}) {
  const fsys = new Map(Object.entries(files));
  const calls: string[] = [];
  const read = (p: string) => {
    const c = fsys.get(p);
    return typeof c === 'function' ? c() : c;
  };
  const exec = (cmd: string, args: string[], input?: string): { code: number; stdout: string } => {
    calls.push([cmd, ...args].join(' '));
    const a = cmd !== 'sudo' ? [cmd, ...args] : args[0] === '-n' ? args.slice(1) : args;
    if (a[0] === 'cat') {
      const c = read(a[1]);
      return c === undefined ? { code: 1, stdout: '' } : { code: 0, stdout: c };
    }
    if (a[0] === 'iptables') {
      const spec = Object.keys(chains).find(k => iptablesListArgs(k).join(' ') === a.slice(1).join(' '));
      return spec ? { code: 0, stdout: chains[spec] } : { code: 1, stdout: '' };
    }
    if (a[0] === 'tee') fsys.set(a[1], input ?? '');
    return { code: 0, stdout: '' };
  };
  const host: Host = {
    run: async (cmd, args, opts) => exec(cmd, args, opts?.input?.toString()).code,
    output: async (cmd, args) => {
      const r = exec(cmd, args);
      return { exitCode: r.code, stdout: r.stdout, stderr: '' };
    }
  };
  return { host, calls, fsys };
}

const CHAINS = { INPUT: 'Chain INPUT (policy ACCEPT)\n', SAFER_RUNNER_OUT: 'Chain SAFER_RUNNER_OUT\n1 REJECT\n' };

/** A runner with the baseline already captured. */
async function captured(chains: Record<string, string> = { ...CHAINS }) {
  const r = runner({ [FILES[0]]: 'corefile\n', [FILES[1]]: 'nameserver 127.0.0.1\n' }, chains);
  await captureBaseline(r.host, FILES, LOGGING);
  r.calls.length = 0;
  return r;
}

describe('captureBaseline', () => {
  it('reads each file and chain, then stores the baseline root-owned 0600', async () => {
    const r = runner({ [FILES[0]]: 'a', [FILES[1]]: 'b' }, CHAINS);
    await captureBaseline(r.host, FILES, LOGGING);
    expect(r.calls).toEqual([
      ...FILES.map(f => `sudo cat ${f}`),
      ...IPTABLES_CHAINS.map(c => `sudo iptables ${iptablesListArgs(c).join(' ')}`),
      ...BASELINE_WRITE_COMMANDS.map(a => `sudo ${a.join(' ')}`)
    ]);
    const state = JSON.parse(r.fsys.get(VALIDATION_STATE_FILE) as string);
    expect(state.files.map((f: { path: string; checksum: string }) => [f.path, f.checksum])).toEqual([
      [FILES[0], sha('a')],
      [FILES[1], sha('b')]
    ]);
    // every monitored chain, an absent one as empty
    expect(state.iptablesRules.map((c: { chain: string }) => c.chain)).toEqual([...IPTABLES_CHAINS]);
    expect(state.iptablesRules[0]).toMatchObject({ rules: CHAINS.INPUT, checksum: sha(CHAINS.INPUT) });
    expect(state.iptablesRules[1]).toMatchObject({ rules: '', checksum: sha('') });
  });

  it('fails, writing nothing, when a file is missing (a setup failure)', async () => {
    const r = runner({ [FILES[0]]: 'a' });
    await expect(captureBaseline(r.host, FILES, LOGGING)).rejects.toThrow(`Critical file ${FILES[1]} missing`);
    expect(r.fsys.has(VALIDATION_STATE_FILE)).toBe(false);
  });

  it('needs sudo logging on first (a compile-time order check)', () => {
    const { host } = runner({});
    // @ts-expect-error - capturing the baseline before sudo logging is on does not compile
    const early = () => captureBaseline(host, FILES, {});
    expect(early).toBeInstanceOf(Function);
  });
});

describe('checkIntegrity (one pass)', () => {
  it('nothing changed: intact, and every file and chain read exactly once', async () => {
    const r = await captured();
    const result = await checkIntegrity(r.host);
    expect(result.intact).toBe(true);
    expect(result.details.status).toBe('verified');
    expect(r.calls).toEqual([
      `sudo -n cat ${VALIDATION_STATE_FILE}`,
      ...FILES.map(f => `sudo cat ${f}`),
      ...IPTABLES_CHAINS.map(c => `sudo iptables ${iptablesListArgs(c).join(' ')}`)
    ]);
  });

  it('a changed file: not intact, shown as TAMPERED', async () => {
    const r = await captured();
    r.fsys.set(FILES[1], 'nameserver 8.8.8.8\n');
    const result = await checkIntegrity(r.host);
    expect(result.intact).toBe(false);
    expect(result.details.status).toBe('tampered');
    expect(result.details.body).toContain(
      `| ${FILES[1]} | ⚠️ TAMPERED | ${sha('nameserver 127.0.0.1\n').slice(0, 16)} -> ${sha('nameserver 8.8.8.8\n').slice(0, 16)} |`
    );
  });

  it('a deleted file: not intact, shown as DELETED', async () => {
    const r = await captured();
    r.fsys.delete(FILES[0]);
    const result = await checkIntegrity(r.host);
    expect(result.intact).toBe(false);
    expect(result.details.body).toContain(
      `| ${FILES[0]} | ⚠️ DELETED | ${sha('corefile\n').slice(0, 16)} -> MISSING |`
    );
  });

  it('a changed chain: not intact', async () => {
    const chains = { ...CHAINS };
    const r = await captured(chains);
    chains.SAFER_RUNNER_OUT = 'Chain SAFER_RUNNER_OUT\n';
    const result = await checkIntegrity(r.host);
    expect(result.intact).toBe(false);
    expect(result.details.body).toContain('| SAFER_RUNNER_OUT | ⚠️ TAMPERED |');
  });

  it('the verdict and the summary come from the same read (they cannot disagree)', async () => {
    // a file that changes between reads: a second pass could see a different state
    let reads = 0;
    const r = runner({ [FILES[0]]: () => (++reads === 1 ? 'x' : `x${reads}`), [FILES[1]]: 'y' });
    await captureBaseline(r.host, FILES, LOGGING);
    reads = 0;
    const result = await checkIntegrity(r.host);
    expect(reads).toBe(1);
    expect(result.intact).toBe(true);
    expect(result.details.status).toBe('verified');
  });

  it('a missing baseline is not intact (unavailable)', async () => {
    const r = runner({});
    expect(await checkIntegrity(r.host)).toEqual({
      intact: false,
      details: { status: 'unavailable', body: 'No validation data available.\n\n' }
    });
  });

  it.each([
    ['not JSON', '{not json'],
    ['without a file list', '{"timestamp":"t"}']
  ])('a baseline that is %s is not intact (tampered)', async (_what, raw) => {
    const r = runner({ [VALIDATION_STATE_FILE]: raw });
    const result = await checkIntegrity(r.host);
    expect(result.intact).toBe(false);
    expect(result.details.status).toBe('tampered');
    expect(result.details.body).toMatch(/^Failed to generate report: /);
  });

  it('a file whose read cannot run is not intact (UNREADABLE)', async () => {
    const r = await captured();
    const output = r.host.output;
    r.host.output = async (cmd, args, opts) => {
      if (args.join(' ') === `cat ${FILES[0]}`) throw new Error('spawn sudo ENOENT');
      return output(cmd, args, opts);
    };
    const result = await checkIntegrity(r.host);
    expect(result.intact).toBe(false);
    expect(result.details.body).toContain(`| ${FILES[0]} | ⚠️ UNREADABLE |`);
  });
});

describe('compare + renderDetails (pure)', () => {
  it('renders the file and chain tables', () => {
    const state = parseBaseline(
      JSON.stringify({
        timestamp: 'T0',
        files: [
          { path: '/a', checksum: 'a'.repeat(64), timestamp: 'T0' },
          { path: '/b', checksum: 'b'.repeat(64), timestamp: 'T0' }
        ],
        iptablesRules: [
          { chain: 'INPUT', rules: '', checksum: 'c'.repeat(64), timestamp: 'T0' },
          { chain: 'DOCKER-USER', rules: '', checksum: 'd'.repeat(64), timestamp: 'T0' }
        ]
      })
    );
    const rows = compare(state, {
      files: new Map([
        ['/a', 'a'.repeat(64)],
        ['/b', null]
      ]),
      chains: new Map([['INPUT', 'e'.repeat(64)]])
    });
    expect(renderDetails(state, rows, 'T1')).toEqual({
      status: 'tampered',
      body:
        '**Baseline:** T0\n**Verified:** T1\n\n' +
        '**Configuration Files**\n\n| File | Status | Checksum Comparison |\n|------|--------|--------------------|\n' +
        `| /a | VERIFIED | ${'a'.repeat(16)} (unchanged) |\n` +
        `| /b | ⚠️ DELETED | ${'b'.repeat(16)} -> MISSING |\n` +
        '\n**Firewall Rules**\n\n| Chain | Status | Checksum Comparison |\n|-------|--------|--------------|\n' +
        `| INPUT | ⚠️ TAMPERED | ${'c'.repeat(16)} -> ${'e'.repeat(16)} |\n` +
        `| DOCKER-USER | ⚠️ MISSING | ${'d'.repeat(16)} -> MISSING |\n` +
        '\n'
    });
  });
});

describe('Baseline storage (M1)', () => {
  it('is root-owned 0600 under /etc/safer-runner, never a runner-writable path', () => {
    const targets = new Set(BASELINE_WRITE_COMMANDS.map(c => c[c.length - 1]));
    expect(Array.from(targets)).toEqual(['/etc/safer-runner/validation-state.json']);
    expect(BASELINE_WRITE_COMMANDS).toContainEqual(['chown', 'root:root', '/etc/safer-runner/validation-state.json']);
    expect(BASELINE_WRITE_COMMANDS).toContainEqual(['chmod', '0600', '/etc/safer-runner/validation-state.json']);
  });

  it('restricts the mode before writing the content', () => {
    const idx = (verb: string) => BASELINE_WRITE_COMMANDS.findIndex(c => c[0] === verb);
    expect(idx('chmod')).toBeLessThan(idx('tee'));
    expect(idx('chown')).toBeLessThan(idx('tee'));
  });

  it("keeps the action's own baseline writes out of the sudo report", () => {
    for (const c of BASELINE_WRITE_COMMANDS) expect(INTERNAL_SUDO_COMMANDS).toContain(c.join(' '));
  });

  it('monitors the config the controls depend on', () => {
    expect(CRITICAL_FILES).toEqual([
      '/etc/safer-runner/Corefile',
      '/etc/resolv.conf',
      '/etc/systemd/resolved.conf.d/no-stub.conf',
      '/etc/safer-runner/policy.json',
      '/opt/safer-runner/proxy/policy.py',
      '/opt/safer-runner/proxy/policy_core.py'
    ]);
  });
});
