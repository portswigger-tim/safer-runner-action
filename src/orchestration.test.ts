/**
 * Orchestration nets: runSetup() and the post step against a recording fake runner.
 *
 * Only EXTERNAL boundaries are faked (@actions/core, @actions/exec, fs, os, dns, net, crypto's
 * randomBytes, fetch, Math.random and the timers), never one of our own modules, so the source
 * can be moved and split freely while these tests keep proving what the runner sees.
 *
 * Each scenario records the ordered transcript of every command, fetch, DNS lookup and exported
 * variable, plus the files setup left behind, and snapshots both. On top of the snapshots, the
 * setup and post-step ordering rules (L1-L29, see setupInvariants) are checked as executable
 * invariants, and a mutation check proves each rule fails when its order is broken.
 */

import { createHash } from 'crypto';
import * as constants from './constants';
import {
  CA_BUNDLE,
  CA_CERT_FILE,
  COREDNS_BIN,
  DNS_LOG,
  FLOW_LOG,
  MITMDUMP_BIN,
  PROXY_CA_KEY_FILE,
  SELFTEST_BOGUS_IP,
  SELFTEST_HOST,
  SUDO_LOG,
  SYSTEM_CA_FILE,
  VALIDATION_STATE_FILE
} from './constants';
import { runSetup, SETUP_MARKER } from './setup/run';
import { readInputs } from './config/inputs';
import { classifySudoCommands, type SudoCommand } from './report/logs/sudo-log';
import {
  INTERNAL_SUDO_COMMANDS,
  SUDO_LOGGING_RSYSLOG_FILE,
  SUDO_LOGGING_SUDOERS_FILE,
  getValidationSudoCommands,
  ruleAllows
} from './services/sudo';

// ------------------------------------------------------------------ external boundaries

jest.mock('@actions/core', () => ({
  getInput: (name: string) => mockHost.inputs[name] ?? '',
  getBooleanInput: (name: string) => (mockHost.inputs[name] ?? '').trim().toLowerCase() === 'true',
  info: (m: string) => mockHost.log.push(`info: ${m}`),
  debug: () => undefined,
  notice: (m: string) => mockHost.log.push(`notice: ${m}`),
  warning: (m: unknown) => mockHost.log.push(`warning: ${String(m)}`),
  error: (m: unknown) => mockHost.log.push(`error: ${String(m)}`),
  setFailed: (m: unknown) => {
    mockHost.log.push(`setFailed: ${String(m)}`);
    mockHost.failed.push(String(m));
  },
  exportVariable: (k: string, v: string) => mockHost.record({ argv: ['<export>', `${k}=${v}`] }),
  group: async (_name: string, fn: () => Promise<unknown>) => fn(),
  startGroup: () => undefined,
  endGroup: () => undefined,
  isDebug: () => false,
  summary: {
    addRaw(md: string) {
      mockHost.summaryText += md;
      return this;
    },
    async write() {
      mockHost.record({ argv: ['<summary.write>'] });
      mockHost.summaryWritten = true;
      return this;
    }
  }
}));

jest.mock('@actions/exec', () => ({
  exec: (cmd: string, args: string[] = [], opts: MockExecOptions = {}) => mockHost.exec(cmd, args, opts),
  getExecOutput: (cmd: string, args: string[] = [], opts: MockExecOptions = {}) =>
    mockHost.getExecOutput(cmd, args, opts)
}));

jest.mock('fs', () => {
  const actual = jest.requireActual('fs');
  const sys = (p: unknown) => typeof p === 'string' && mockHost.owns(p);
  return {
    ...actual,
    existsSync: (p: string) => (sys(p) ? mockHost.files.has(p) : actual.existsSync(p)),
    readFileSync: (p: string, enc?: unknown) => (sys(p) ? mockHost.readFile(p, enc) : actual.readFileSync(p, enc)),
    statSync: (p: string) => (sys(p) ? { size: Buffer.byteLength(mockHost.readFile(p, 'utf8')) } : actual.statSync(p)),
    accessSync: (p: string, mode?: number) => (sys(p) ? mockHost.access(p) : actual.accessSync(p, mode)),
    realpathSync: (p: string) => (sys(p) ? p : actual.realpathSync(p))
  };
});

jest.mock('os', () => ({ ...jest.requireActual('os'), hostname: () => 'fv-az123-456' }));

jest.mock('crypto', () => ({
  ...jest.requireActual('crypto'),
  randomBytes: (n: number) => Buffer.alloc(n, 0xab)
}));

jest.mock('net', () => ({
  ...jest.requireActual('net'),
  createServer: () => {
    const srv = {
      once: () => srv,
      listen: (o: { port: number }, cb: () => void) => {
        mockHost.record({ argv: ['<net.listen>', String(o.port)] });
        cb();
        return srv;
      },
      close: (cb: () => void) => cb()
    };
    return srv;
  }
}));

jest.mock('dns', () => {
  const actual = jest.requireActual('dns');
  class Resolver {
    setServers(): void {
      // the resolver address is fixed (DNS_LISTEN)
    }
    resolve4(name: string): Promise<string[]> {
      return mockHost.resolve(name);
    }
  }
  return {
    ...actual,
    promises: {
      ...actual.promises,
      Resolver,
      lookup: async (name: string) => {
        mockHost.record({ argv: ['<dns.lookup>', name] });
        return [{ address: '10.1.0.4', family: 4 }];
      }
    }
  };
});

// ------------------------------------------------------------------ the fake runner

interface MockExecOptions {
  input?: Buffer;
  ignoreReturnCode?: boolean;
  silent?: boolean;
  listeners?: { stdout?: (b: Buffer) => void };
}
interface Entry {
  argv: string[];
  input?: string;
  /** run with ignoreReturnCode: a failure does not throw, so the call site must check the code */
  ignore?: true;
  silent?: true;
}
interface Result {
  code: number;
  stdout?: string;
  stderr?: string;
}

const ACTION_SCRIPT = '/home/runner/work/_actions/portswigger-tim/safer-runner-action/v2.3.0/dist/pre/index.js';
const SYSTEM_ROOTS = ['/etc', '/var', '/opt', '/run', '/usr', '/tmp', '/home/runner', '/.dockerenv'];
const FAKE_CERT = '-----BEGIN CERTIFICATE-----\nMIIBfake1\nMIIBfake2\nMIIBfake3\n-----END CERTIFICATE-----\n';
const JDK = '/usr/lib/jvm/temurin-17-jdk-amd64';
const CONTAINER_IDS = ['c0ffee0000000000000000000000000000000000000000000000000000000001'];
const CANARY = '5ec7e7c0ffee1234';

const META = {
  domains: {
    actions: [
      'github.com',
      '*.github.com',
      '*.actions.githubusercontent.com',
      'objects.githubusercontent.com',
      'productionresultssa1.blob.core.windows.net'
    ],
    artifact_attestations: { services: ['*.actions.githubusercontent.com', 'fulcio.githubapp.com'] }
  }
};

interface Scenario {
  name: string;
  inputs: Record<string, string>;
  flavour: 'sudo' | 'sudo-rs';
  docker: { active: boolean; dockerUser: boolean; containers: string[] };
}

class FakeHost {
  inputs: Record<string, string> = {};
  log: string[] = [];
  failed: string[] = [];
  transcript: Entry[] = [];
  files = new Map<string, string>();
  seeded = new Map<string, string>();
  summaryText = '';
  summaryWritten = false;

  mode: 'analyze' | 'enforce' = 'analyze';
  flavour: 'sudo' | 'sudo-rs' = 'sudo';
  docker = { active: true, dockerUser: true, inGroup: true, socketLocked: false, containers: [] as string[] };
  users = new Set<string>();
  /** transient units started (systemd-run) */
  units = new Set<string>();
  proxyUp = false;
  dnsUp = false;
  sudoLogging = false;
  sudoRestricted = false;
  /** ip6tables-restore fails (a kernel without ip6tables support) */
  ip6RestoreFails = false;
  /** a command line (`cmd args...`) that exits 1 */
  failing: RegExp | null = null;
  /** bumped on every ruleset applied, and by a tampering step */
  iptablesGeneration = 0;

  owns(p: string): boolean {
    return SYSTEM_ROOTS.some(r => p === r || p.startsWith(`${r}/`));
  }

  seed(path: string, content: string): void {
    this.files.set(path, content);
    this.seeded.set(path, content);
  }

  record(e: Entry): void {
    this.transcript.push(e);
  }

  readFile(p: string, enc?: unknown): string | Buffer {
    const c = this.files.get(p);
    if (c === undefined) {
      throw Object.assign(new Error(`ENOENT: no such file or directory, open '${p}'`), { code: 'ENOENT' });
    }
    return enc ? c : Buffer.from(c);
  }

  append(p: string, text: string): void {
    this.files.set(p, (this.files.get(p) ?? '') + text);
  }

  access(p: string): void {
    if (p === '/var/run/docker.sock' && this.files.has(p) && !this.docker.socketLocked) return;
    throw Object.assign(new Error(`EACCES: permission denied, access '${p}'`), { code: 'EACCES' });
  }

  async resolve(name: string): Promise<string[]> {
    this.record({ argv: ['<dns.query>', name] });
    if (!this.dnsUp) throw Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' });
    if (name.startsWith('srst-')) {
      this.append(
        DNS_LOG,
        `[INFO] 127.0.0.1:41452 ${this.mode === 'enforce' ? 'BLOCK' : 'WOULD_BLOCK'} A ${name}. NXDOMAIN\n`
      );
      throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
    }
    return ['140.82.112.3'];
  }

  async exec(cmd: string, args: string[], opts: MockExecOptions): Promise<number> {
    const r = this.run(cmd, args, opts);
    if (r.stdout && opts.listeners?.stdout) opts.listeners.stdout(Buffer.from(r.stdout));
    if (r.code !== 0 && !opts.ignoreReturnCode) {
      throw new Error(`The process '${cmd}' failed with exit code ${r.code}`);
    }
    return r.code;
  }

  async getExecOutput(
    cmd: string,
    args: string[],
    opts: MockExecOptions
  ): Promise<{ exitCode: number; stdout: string; stderr: string }> {
    const exitCode = await this.exec(cmd, args, { ...opts, listeners: undefined });
    const r = this.lastResult;
    return { exitCode, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  }

  private lastResult: Result = { code: 0 };

  private run(cmd: string, args: string[], opts: MockExecOptions): Result {
    const { input } = opts;
    this.record({
      argv: [cmd, ...args],
      ...(input ? { input: input.toString('utf8') } : {}),
      ...(opts.ignoreReturnCode ? { ignore: true } : {}),
      ...(opts.silent ? { silent: true } : {})
    });
    let r: Result;
    if (this.failing?.test([cmd, ...args].join(' '))) {
      r = { code: 1, stderr: 'injected failure' };
    } else if (cmd === 'sudo' && args[0] === '--version') {
      r = { code: 0, stdout: this.flavour === 'sudo-rs' ? 'sudo-rs 0.2.13-0ubuntu1.2\n' : 'Sudo version 1.9.15p5\n' };
    } else if (cmd === 'sudo') {
      const a = sudoArgv(args);
      const denied =
        this.sudoRestricted && !installedSudoersAllows(this.files.get('/etc/sudoers.d/runner') ?? '', args);
      if (this.sudoLogging) this.logSudo(a, denied);
      r = denied ? { code: 1, stderr: 'sudo: a password is required' } : this.handle(a, input, true);
    } else {
      r = this.handle([cmd, ...args], input, false);
    }
    this.lastResult = r;
    return r;
  }

  private logSudo(a: string[], denied: boolean): void {
    const why = denied ? 'command not allowed ; ' : '';
    this.append(SUDO_LOG, `Nov  7 12:00:00 : runner : ${why}PWD=/home/runner ; USER=root ; COMMAND=${absCommand(a)}\n`);
  }

  private handle(a: string[], input: Buffer | undefined, root: boolean): Result {
    const ok = (stdout = ''): Result => ({ code: 0, stdout });
    const [c] = a;
    switch (c) {
      case 'tee':
        this.files.set(a[1], input?.toString('utf8') ?? '');
        return ok();
      case 'touch':
        if (!this.files.has(a[1])) this.files.set(a[1], '');
        return ok();
      case 'cat':
        return this.files.has(a[1]) ? ok(this.files.get(a[1])) : { code: 1, stderr: 'No such file or directory' };
      case 'unlink':
        this.files.delete(a[1]);
        return ok();
      case 'rm':
        for (const p of a.slice(1).filter(x => !x.startsWith('-'))) this.files.delete(p);
        return ok();
      case 'mv': {
        const [from, to] = a.slice(1);
        this.files.set(to, this.files.get(from) ?? '');
        this.files.delete(from);
        if (to === SUDO_LOGGING_SUDOERS_FILE) this.sudoLogging = true;
        if (to === '/etc/sudoers.d/runner') this.sudoRestricted = true;
        return ok();
      }
      case 'install': {
        if (a[1] === '-d') return ok();
        const [src, dest] = a.slice(-2);
        this.files.set(dest, this.files.get(src) ?? `<copy of ${src}>\n`);
        return ok();
      }
      case 'chmod':
        if (a[2] === '/var/run/docker.sock') this.docker.socketLocked = true;
        return ok();
      case 'chown':
      case 'mkdir':
      case 'sysctl':
      case 'apt-get':
      case 'nproc':
      case 'visudo':
        return ok();
      case 'useradd':
        this.users.add(a[a.length - 1]);
        return ok();
      case 'id':
        if (a[1] === '-u') return this.users.has(a[2]) ? ok('998\n') : { code: 1, stderr: 'no such user' };
        return ok(this.docker.inGroup ? 'runner adm users docker\n' : 'runner adm users\n');
      case 'gpasswd':
        this.docker.inGroup = false;
        return ok();
      case 'update-ca-certificates':
        this.files.set(CA_BUNDLE, `SYSTEM ROOTS\n${this.files.get(SYSTEM_CA_FILE) ?? ''}`);
        return ok();
      case 'sh':
        if (a[2].includes('openssl')) {
          const [key, cert, , pem] = a.slice(4);
          void key;
          this.files.set(cert, FAKE_CERT);
          this.files.set(pem, `FAKE PRIVATE KEY\n${FAKE_CERT}`);
          return ok();
        }
        return a[2] === 'command -v conntrack' ? ok('/usr/sbin/conntrack\n') : { code: 127 };
      case 'systemctl':
        return this.systemctl(a);
      case 'systemd-run': {
        const unit = a.find(x => x.startsWith('--unit='))?.slice(7);
        if (unit) this.units.add(unit);
        if (unit === constants.PROXY_UNIT) {
          this.proxyUp = true;
          // the addon's own startup record (python json.dumps spacing)
          this.append(FLOW_LOG, `{"ev": "start", "ok": true, "pid": 4242, "mode": "${this.mode}"}\n`);
        }
        if (unit === constants.DNS_UNIT) this.dnsUp = true;
        return ok();
      }
      case 'ss':
        if (a[1] === '-Hltn') {
          const port = a[2].split(':')[1];
          return ok(this.proxyUp ? `LISTEN 0 4096 127.0.0.1:${port} 0.0.0.0:*\n` : '');
        }
        return ok();
      case 'iptables':
      case 'ip6tables':
        return this.iptables(a);
      case 'iptables-restore':
      case 'ip6tables-restore':
        if (c === 'ip6tables-restore' && this.ip6RestoreFails)
          return { code: 2, stderr: 'ip6tables-restore: line 3 failed' };
        this.iptablesGeneration++;
        return ok();
      case 'ip':
        return ok('default via 10.1.0.1 dev eth0 proto dhcp src 10.1.0.4 metric 100\n');
      case 'docker':
        return this.dockerCli(a, root);
      case 'conntrack':
        return { code: 1 }; // nothing matched
      case 'curl':
        return this.curl(a);
      default:
        if (c.endsWith('/bin/keytool')) return ok();
        throw new Error(`fake runner: unhandled command: ${a.join(' ')}`);
    }
  }

  private systemctl(a: string[]): Result {
    const [, verb, ...rest] = a;
    const unit = rest.filter(x => !x.startsWith('-'))[0];
    const dockerUnit = unit === 'docker' || unit === 'docker.service' || unit === 'docker.socket';
    if (verb === 'is-active') return { code: (dockerUnit && this.docker.active) || this.units.has(unit) ? 0 : 3 };
    if (verb === 'stop' && dockerUnit) this.docker.active = false;
    if (verb === 'restart' && unit === 'rsyslog' && this.files.has(SUDO_LOGGING_RSYSLOG_FILE)) this.sudoLogging = true;
    return { code: 0 };
  }

  private iptables(a: string[]): Result {
    const chain = a[a.indexOf('-L') + 1];
    if (a.includes('-L') && a.includes('-t') && a.includes('filter')) return { code: this.docker.dockerUser ? 0 : 1 };
    if (a.includes('-D')) return { code: 1 }; // no jump left to delete
    if (a.includes('-L')) {
      const table = a.includes('-t') ? a[a.indexOf('-t') + 1] : 'filter';
      const missing =
        !this.docker.dockerUser && ['DOCKER-USER', 'SAFER_RUNNER_CFWD', 'SAFER_RUNNER_CNAT'].includes(chain);
      if (missing) return { code: 1, stderr: `iptables: No chain/target/match by that name.` };
      return {
        code: 0,
        stdout: `Chain ${chain} (${table}, ruleset ${this.iptablesGeneration})\nnum  target  prot opt source  destination\n`
      };
    }
    return { code: 0 };
  }

  private dockerCli(a: string[], root: boolean): Result {
    const usable = this.docker.active && (root || !this.docker.socketLocked);
    if (!usable) return { code: 1, stderr: 'permission denied while trying to connect to the Docker daemon socket' };
    const sub = a.slice(1).join(' ');
    if (sub === 'ps -q --no-trunc' || sub === 'ps -aq') return { code: 0, stdout: this.docker.containers.join('\n') };
    if (sub.startsWith('info')) return { code: 0, stdout: '27.3.1\n' };
    if (sub.startsWith('network ls')) return { code: 0, stdout: 'f00dbabe0001\n' };
    if (sub.startsWith('network inspect')) {
      return {
        code: 0,
        stdout: JSON.stringify([{ Driver: 'bridge', IPAM: { Config: [{ Subnet: '172.17.0.0/16' }] } }])
      };
    }
    if (a[1] === 'inspect' && a[3].includes('Healthcheck')) {
      // the service container has a healthcheck; anything else is gone (exit 1, like docker)
      const known = a.slice(4).filter(id => this.docker.containers.includes(id));
      const lines = known.map(
        id => `${JSON.stringify(id)}\t${JSON.stringify({ Test: ['CMD-SHELL', 'pg_isready -U postgres'] })}\tnull`
      );
      return { code: known.length === a.length - 4 ? 0 : 1, stdout: lines.join('\n') + '\n' };
    }
    if (a[1] === 'inspect') return { code: 0, stdout: '/redis 172.17.0.2\n' };
    throw new Error(`fake runner: unhandled docker command: ${a.join(' ')}`);
  }

  private curl(a: string[]): Result {
    const resolve = a[a.indexOf('--resolve') + 1] ?? '';
    if (resolve.startsWith(`${SELFTEST_HOST}:`)) {
      const verdict = this.mode === 'enforce' ? 'BLOCK' : 'WOULD_BLOCK';
      this.append(
        FLOW_LOG,
        JSON.stringify({
          ev: 'tls',
          verdict,
          reason: 'sni-not-allowed',
          layer: 'sni',
          sni: SELFTEST_HOST,
          client: '10.1.0.4:50000',
          dst: `${SELFTEST_BOGUS_IP}:443`
        }) + '\n'
      );
      return { code: 35, stdout: '000', stderr: 'curl: (35) TLS connect error' };
    }
    if (resolve.startsWith('github.com:')) {
      this.append(
        FLOW_LOG,
        JSON.stringify({
          ev: 'tls',
          verdict: 'INTERCEPT',
          reason: 'allowed',
          layer: 'sni',
          sni: 'github.com',
          client: '10.1.0.4:50001',
          dst: `${SELFTEST_BOGUS_IP}:443`,
          repointed: true
        }) +
          '\n' +
          JSON.stringify({
            ev: 'https',
            verdict: 'ALLOW',
            reason: 'allowed',
            layer: 'http',
            host: 'github.com',
            sni: 'github.com',
            method: 'GET',
            path: '/robots.txt',
            status: 200,
            client: '10.1.0.4:50001',
            dst: `${SELFTEST_BOGUS_IP}:443`,
            upstream: '140.82.112.3:443'
          }) +
          '\n'
      );
      return { code: 0, stdout: '200' };
    }
    throw new Error(`fake runner: unexpected curl: ${a.join(' ')}`);
  }
}

// eslint-disable-next-line no-var
var mockHost: FakeHost;

/** The command sudo runs: flags (-n, -E, -u user) stripped. */
function sudoArgv(args: string[]): string[] {
  const a = [...args];
  while (a[0] === '-n' || a[0] === '-E') a.shift();
  if (a[0] === '-u') a.splice(0, 2);
  return a;
}

/** The command as sudo logs it (absolute path). */
function absCommand(a: string[]): string {
  const bin = a[0].startsWith('/') ? a[0] : `${/tables/.test(a[0]) ? '/usr/sbin' : '/usr/bin'}/${a[0]}`;
  return [bin, ...a.slice(1)].join(' ');
}

/** Does the restricted sudoers (getValidationSudoCommands) allow `sudo <args>`? */
function sudoersAllows(args: string[]): boolean {
  const allowed = new Set(getValidationSudoCommands().map(c => c.replace(/^\/usr\/s?bin\//, '')));
  return allowed.has(sudoArgv(args).join(' '));
}

/** The command rules of a sudoers file as sudo reads them (a bare command would allow any arguments). */
function sudoersRules(text: string): { path: string; args: string[]; anyRest: boolean }[] {
  return text
    .replace(/\\\n\s*/g, '')
    .split('\n')
    .filter(l => l.startsWith('Cmnd_Alias '))
    .flatMap(l => l.replace(/^Cmnd_Alias \w+ = /, '').split(', '))
    .map(e => {
      const w = e.trim().split(' ');
      const lastWord = w[w.length - 1];
      if (w.length === 1) return { path: w[0], args: [], anyRest: true }; // bare: any arguments
      if (lastWord === '""') return { path: w[0], args: [], anyRest: false };
      return lastWord === '*'
        ? { path: w[0], args: w.slice(1, -1), anyRest: true }
        : { path: w[0], args: w.slice(1), anyRest: false };
    });
}

/** Does the installed sudoers allow `sudo <args>`? */
function installedSudoersAllows(text: string, args: string[]): boolean {
  const [cmd, ...rest] = absCommand(sudoArgv(args)).split(' ');
  return sudoersRules(text).some(r =>
    r.anyRest && !r.args.length ? r.path === cmd : ruleAllows(r, cmd, rest.join(' '))
  );
}

// ------------------------------------------------------------------ driving

const NOW = new Date('2026-11-07T12:00:00Z');
const savedArgv = process.argv[1];
const savedEnv = { ...process.env };

/** Run a promise to completion while advancing the fake clock (polls, sleeps, deadlines). */
async function settle<T>(p: Promise<T>): Promise<T> {
  let state: { done: boolean; value?: T; error?: unknown } = { done: false };
  p.then(
    value => (state = { done: true, value }),
    error => (state = { done: true, error })
  );
  for (let i = 0; i < 5000 && !state.done; i++) await jest.advanceTimersByTimeAsync(100);
  if (!state.done) throw new Error('did not settle');
  if (state.error) throw state.error;
  return state.value as T;
}

function newHost(s: Scenario): FakeHost {
  const h = new FakeHost();
  mockHost = h;
  h.inputs = s.inputs;
  h.mode = s.inputs.mode === 'enforce' ? 'enforce' : 'analyze';
  h.flavour = s.flavour;
  h.docker = { ...s.docker, inGroup: true, socketLocked: false };
  h.seed(MITMDUMP_BIN, '<mitmdump>');
  h.seed(COREDNS_BIN, '<coredns>');
  h.seed('/etc/hosts', '127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n');
  h.seed('/etc/resolv.conf', 'nameserver 127.0.0.53\n');
  h.seed(`${JDK}/lib/security/cacerts`, '<cacerts>');
  h.seed(`${JDK}/bin/keytool`, '<keytool>');
  if (s.docker.active) h.seed('/var/run/docker.sock', '');
  return h;
}

async function setup(s: Scenario): Promise<FakeHost> {
  const h = newHost(s);
  await settle(runSetup(readInputs()));
  return h;
}

/** Run the post step (it starts on import) to completion. */
async function post(h: FakeHost): Promise<void> {
  h.transcript = [];
  h.log = [];
  jest.isolateModules(() => {
    require('./post');
  });
  for (let i = 0; i < 400 && !(h.summaryWritten && jest.getTimerCount() === 0); i++) {
    await jest.advanceTimersByTimeAsync(100);
  }
  for (let i = 0; i < 10; i++) await jest.advanceTimersByTimeAsync(0);
}

const ts = (s: string) => s.replace(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g, '<ts>');
const line = (e: Entry) => e.argv.join(' ');

/** One line per entry; exec options as `[ignore-rc]` / `[silent]`, stdin as its size and hash. */
function transcriptText(t: Entry[]): string {
  return t
    .map(e => {
      const opts = `${e.ignore ? ' [ignore-rc]' : ''}${e.silent ? ' [silent]' : ''}`;
      if (e.input === undefined) return `$ ${line(e)}${opts}`;
      const sha = createHash('sha256').update(ts(e.input)).digest('hex').slice(0, 12);
      return `$ ${line(e)}${opts}  <<< ${Buffer.byteLength(e.input)} bytes, sha256:${sha}`;
    })
    .join('\n');
}

/** Files setup created or changed (content with timestamps normalised). */
function writtenFiles(h: FakeHost): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [p, c] of [...h.files.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    if (h.seeded.get(p) !== c) out[p] = ts(c);
  }
  return out;
}

// ------------------------------------------------------------------ invariants (L1-L29)

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const re = (s: string) => new RegExp(`^${esc(s)}`);
const first = (t: Entry[], r: RegExp) => t.findIndex(e => r.test(line(e)));
function last(t: Entry[], r: RegExp): number {
  for (let i = t.length - 1; i >= 0; i--) if (r.test(line(t[i]))) return i;
  return -1;
}

const P = {
  meta: re('<fetch> https://api.github.com/meta'),
  hostLookup: re('<dns.lookup> '),
  portProbe: re('<net.listen> '),
  policyWrite: re(`sudo tee ${constants.POLICY_FILE}`),
  dnsUserAdd: /^sudo useradd .* dns-[0-9a-f]+$/,
  proxyUserAdd: re(`sudo useradd --system --no-create-home --shell /usr/sbin/nologin ${constants.PROXY_USER}`),
  caGenerate: re(`sudo -u ${constants.PROXY_USER} sh -c umask 077 && openssl req`),
  addonCore: new RegExp(
    `^sudo install -m 0644 -o root -g root \\S+/proxy/policy_core\\.py ${esc(constants.ADDON_DIR)}/policy_core\\.py$`
  ),
  flowLogTouch: re(`sudo touch ${FLOW_LOG}`),
  dnsLogTouch: re(`sudo touch ${DNS_LOG}`),
  proxyRun: re(`sudo systemd-run --unit=${constants.PROXY_UNIT}`),
  dnsRun: re(`sudo systemd-run --unit=${constants.DNS_UNIT}`),
  proxyListening: re('ss -Hltn sport = :'),
  caToStore: re(`sudo install -m 0644 -o root -g root ${CA_CERT_FILE} ${SYSTEM_CA_FILE}`),
  updateCa: re('sudo update-ca-certificates'),
  nodeCaEnv: re(`<export> NODE_EXTRA_CA_CERTS=${CA_CERT_FILE}`),
  javaImport: /^sudo \S+\/bin\/keytool -importcert /,
  resolvedDropIn: re('sudo tee /etc/systemd/resolved.conf.d/no-stub.conf'),
  resolvUnlink: re('sudo unlink /etc/resolv.conf'),
  resolvWrite: re('sudo tee /etc/resolv.conf'),
  resolvedRestart: re('sudo systemctl restart systemd-resolved'),
  dnsReadyProbe: re('<dns.query> github.com'),
  dockerReload: re('sudo systemctl reload docker'),
  dockerRestart: re('sudo systemctl restart docker'),
  dockerUserProbe: re('sudo iptables -t filter -n -L DOCKER-USER'),
  jumpDelete: /^sudo i(p6)?ptables -t \S+ -D /,
  chainFlush: re(`sudo iptables -t filter -X ${constants.FILTER_CHAIN}`),
  iptablesLogRule: re('sudo tee /etc/rsyslog.d/10-iptables-safer-runner-v2.conf'),
  routeLocalnet: re('sudo sysctl -q -w net.ipv4.conf.all.route_localnet=1'),
  restore4: re('sudo iptables-restore --noflush'),
  restore6: re('sudo ip6tables-restore --noflush'),
  killFlows: re('sudo ss -K '),
  conntrack: re('sudo conntrack -D '),
  curl: re('curl '),
  selftestWrite: re(`sudo tee ${constants.SELFTEST_FILE}`),
  dockerPolicy:
    /^sudo (gpasswd -d runner docker|chown root:root \/var\/run\/docker\.sock|chmod 600 \/var\/run\/docker\.sock|systemctl (stop|disable) docker\.(socket|service))$/,
  /** anything that changes who can use docker, or whether it runs (wider than what setup does) */
  dockerAccessChange:
    /^sudo ((gpasswd|usermod|deluser|groupmod)\b.*\bdocker\b|(chown|chmod|chgrp|setfacl|rm|mv)\b.*docker\.sock|systemctl (stop|disable|mask|kill) docker(\.(socket|service))?$)/,
  dockerEventsRun: re(`sudo systemd-run --unit=${constants.DOCKER_EVENTS_UNIT}`),
  marker: re(`sudo tee ${SETUP_MARKER}`),
  loggingClassic: re(`sudo mv /tmp/safer-runner-sudo-logging.tmp ${SUDO_LOGGING_SUDOERS_FILE}`),
  loggingRsTee: re(`sudo tee ${SUDO_LOGGING_RSYSLOG_FILE}`),
  baselineTouch: re(`sudo touch ${VALIDATION_STATE_FILE}`),
  baselineChown: re(`sudo chown root:root ${VALIDATION_STATE_FILE}`),
  baselineChmod: re(`sudo chmod 0600 ${VALIDATION_STATE_FILE}`),
  baselineTee: re(`sudo tee ${VALIDATION_STATE_FILE}`),
  visudo: re('sudo visudo -c -f /tmp/runner-sudoers.tmp'),
  sudoersChmod: re('sudo chmod 0440 /tmp/runner-sudoers.tmp'),
  sudoersChown: re('sudo chown root:root /tmp/runner-sudoers.tmp'),
  sudoersMv: re('sudo mv /tmp/runner-sudoers.tmp /etc/sudoers.d/runner'),
  baselineRead: re(`sudo -n cat ${VALIDATION_STATE_FILE}`),
  summary: re('<summary.write>')
};

/** Commands that apply the firewall or sudoers: a silent failure here would leave the job open. */
const FAIL_CLOSED =
  /^sudo (ip6?tables-restore |(tee|visudo -c -f|chmod 0440|chown root:root|mv) \/tmp\/(runner-sudoers|safer-runner-sudo-logging)\.tmp)/;
/**
 * Ignored on purpose because the caller checks the code: applyFirewall throws in enforce when
 * ip6tables-restore fails (tested below); restrictSudo throws when visudo rejects the
 * file (services/sudo/index.test.ts).
 */
const CHECKED_IGNORES = [P.restore6, P.visudo];

interface Expect {
  mode: 'analyze' | 'enforce';
  disableSudo: boolean;
  flavour: 'sudo' | 'sudo-rs';
  dockerRestart: boolean;
  containerRules: boolean;
  /** the scenario's sudo-config, one normalised line each, as the restricted sudoers must hold them */
  sudoConfig?: string[];
}

/** Index where sudo logging is on: every later sudo command lands in the sudo log. */
function loggingStart(t: Entry[], flavour: 'sudo' | 'sudo-rs'): number {
  if (flavour === 'sudo') return first(t, P.loggingClassic);
  const tee = first(t, P.loggingRsTee);
  const restart = t.findIndex((e, i) => i > tee && line(e) === 'sudo systemctl restart rsyslog');
  return tee < 0 ? -1 : restart;
}

/**
 * The setup ordering and privilege rules, checked over the transcript. Returns the broken ones
 * (empty: all hold). Each is tagged with its landmine id from the migration plan.
 */
function setupInvariants(t: Entry[], x: Expect): string[] {
  const v: string[] = [];
  const at = (r: RegExp, lastOne = false) => (lastOne ? last(t, r) : first(t, r));
  const before = (id: string, a: RegExp, b: RegExp, o: { optional?: boolean; aLast?: boolean } = {}) => {
    const i = at(a, o.aLast);
    const j = at(b);
    if (i < 0 || j < 0) {
      if (!o.optional) v.push(`${id}: missing ${i < 0 ? a : b}`);
      return;
    }
    if (i >= j) v.push(`${id}: ${a} must come before ${b}`);
  };

  before('L1', P.meta, P.resolvWrite);
  before('L1', P.meta, P.restore4);
  before('L2', P.hostLookup, P.resolvWrite);
  before('L3', P.portProbe, P.policyWrite, { aLast: true });
  before('L5', P.dnsUserAdd, P.restore4);
  before('L5', P.proxyUserAdd, P.caGenerate);
  before('L6', P.addonCore, P.proxyRun);
  before('L6', P.policyWrite, P.proxyRun);
  before('L7', P.flowLogTouch, P.proxyRun);
  before('L7', P.dnsLogTouch, P.dnsRun);
  before('L8', P.caGenerate, P.proxyRun);
  if (t.some(e => e.argv[0] === 'sudo' && e.argv[1] === 'tee' && e.argv[2].startsWith(constants.PROXY_CONF_DIR))) {
    v.push('L8: the CA key directory must only be written by the openssl step run as the proxy user');
  }
  before('L9', P.proxyRun, P.proxyListening);
  before('L9', P.proxyListening, P.restore4, { aLast: true });
  before('L9', P.proxyRun, P.caToStore);
  before('L10', P.caToStore, P.updateCa);
  before('L10', P.updateCa, P.restore4);
  before('L10', P.nodeCaEnv, P.restore4);
  before('L10', P.javaImport, P.restore4);
  before('L10', P.updateCa, P.dockerRestart, { optional: !x.dockerRestart });
  before('L11', P.dnsRun, P.dnsReadyProbe);
  before('L11', P.dnsReadyProbe, P.resolvWrite);
  before('L11', P.resolvedDropIn, P.resolvUnlink);
  before('L11', P.resolvUnlink, P.resolvWrite);
  before('L11', P.resolvWrite, P.resolvedRestart);
  // the firewall forces :53 to CoreDNS only once the system resolver points at it
  before('L11', P.resolvWrite, P.restore4);
  if (x.dockerRestart) {
    before('L12', P.dockerReload, P.dockerRestart);
    before('L12', P.dockerRestart, P.restore4);
  } else if (first(t, P.dockerRestart) >= 0) {
    v.push('L12: dockerd restarted when it should not have been');
  }
  if (x.containerRules) before('L13', P.dockerUserProbe, P.jumpDelete);
  before('L14', P.iptablesLogRule, P.restore4);
  before('L14', P.chainFlush, P.routeLocalnet);
  before('L14', P.routeLocalnet, P.restore4);
  before('L14', P.restore4, P.restore6);
  before('L14', P.restore6, P.killFlows);
  if (x.containerRules) before('L14', P.restore6, P.conntrack);
  before('L15', P.restore6, P.curl);
  before('L15', P.curl, P.selftestWrite, { aLast: true });
  before('L16', P.selftestWrite, P.dockerPolicy, { optional: true });
  before('L17', P.dockerPolicy, P.marker, { optional: true, aLast: true });
  before('L17', P.selftestWrite, P.marker);

  // the baseline (and everything after it) runs with sudo logging on (sudo-rs: see loggingStart)
  before('L18', x.flavour === 'sudo' ? P.loggingClassic : P.loggingRsTee, P.baselineTouch);
  const logging = loggingStart(t, x.flavour);
  const markerAt = at(P.marker);
  if (logging < 0) v.push('L18: sudo logging was never turned on');
  else {
    if (markerAt > logging) v.push('L18: sudo logging must start after the setup marker');
    const baseline = at(P.baselineTouch);
    if (baseline >= 0 && baseline < logging) v.push('L18: sudo logging must be on before the baseline is written');
    // L20: from here on every sudo command is in the sudo log, and must be the action's own
    const after: SudoCommand[] = t
      .slice(logging + 1)
      .filter(e => e.argv[0] === 'sudo')
      .map(e => {
        const a = sudoArgv(e.argv.slice(1));
        return {
          timestamp: '',
          user: 'runner',
          targetUser: 'root',
          command: absCommand(a).split(' ')[0],
          args: a.slice(1).join(' ')
        };
      });
    const usage = classifySudoCommands(after, INTERNAL_SUDO_COMMANDS);
    for (const c of usage.ran)
      v.push(`L20: sudo command after logging started is not in INTERNAL_SUDO_COMMANDS: ${c.command} ${c.args}`);
  }

  before('L19', P.baselineTouch, P.baselineChown);
  before('L19', P.baselineChown, P.baselineChmod);
  before('L19', P.baselineChmod, P.baselineTee);
  const teeAt = at(P.baselineTee);
  if (teeAt >= 0 && t.slice(0, teeAt).some(e => P.baselineTee.test(line(e)))) v.push('L19: baseline written twice');

  if (x.mode === 'enforce' && x.disableSudo) {
    before('L21', P.baselineTee, P.visudo);
    before('L21', P.visudo, P.sudoersChmod);
    before('L21', P.sudoersChmod, P.sudoersMv);
    before('L21', P.sudoersChown, P.sudoersMv);
    const lastSudo = last(t, /^sudo /);
    if (lastSudo !== at(P.sudoersMv)) v.push('L21: restricting sudo must be the last privileged step');
  } else if (at(P.sudoersMv) >= 0) {
    v.push('L21: sudo restricted although disable-sudo is off or the mode is analyze');
  }

  // L26: analyze never changes sudo (it evaluates the policy in the post step instead)
  if (x.mode === 'analyze') {
    const touched = t.filter(e => /\/tmp\/runner-sudoers\.tmp|\/etc\/sudoers\.d\/runner/.test(line(e)));
    for (const e of touched) v.push(`L26: analyze changed the runner's sudoers: ${line(e)}`);
  }

  // L28: analyze never changes docker access (it evaluates the docker policy in the post step)
  if (x.mode === 'analyze') {
    for (const e of t.filter(e => P.dockerAccessChange.test(line(e)))) {
      v.push(`L28: analyze changed docker access: ${line(e)}`);
    }
  }

  // L27: the restricted sudoers is exactly the validation commands plus the job's sudo-config
  // lines, as root only; a command with no arguments carries "" (bare, it would allow any)
  const sudoersTee = t.find(e => line(e) === 'sudo tee /tmp/runner-sudoers.tmp');
  if (sudoersTee) {
    const job = x.sudoConfig ?? [];
    const rules = (sudoersTee.input ?? '')
      .replace(/\\\n\s*/g, '')
      .split('\n')
      .filter(l => l.trim() && !l.startsWith('#'));
    const expected = [
      `Cmnd_Alias SAFER_RUNNER_VALIDATION = ${getValidationSudoCommands().join(', ')}`,
      'runner ALL=(ALL) NOPASSWD: SAFER_RUNNER_VALIDATION',
      ...(job.length
        ? [
            `Cmnd_Alias SAFER_RUNNER_JOB = ${job.map(l => (l.includes(' ') ? l : `${l} ""`)).join(', ')}`,
            'runner ALL=(root) NOPASSWD: SAFER_RUNNER_JOB'
          ]
        : [])
    ];
    if (JSON.stringify(rules) !== JSON.stringify(expected)) {
      v.push(`L27: the restricted sudoers is not the validation commands plus sudo-config: ${JSON.stringify(rules)}`);
    }
  }

  // L29: analyze records the use of docker (read only) once dockerd has settled, and only when
  // dockerd already runs (never started through socket activation); enforce never does
  const recording = x.mode === 'analyze' && x.containerRules;
  if (recording) {
    before('L29', P.dockerRestart, P.dockerEventsRun, { optional: !x.dockerRestart });
    before('L29', P.selftestWrite, P.dockerEventsRun);
    before('L29', P.dockerEventsRun, P.marker);
    const run = t.find(e => P.dockerEventsRun.test(line(e)));
    if (run && !(run.argv.includes('Restart=no') && run.argv.includes('PrivateNetwork=yes'))) {
      v.push('L29: the docker events recorder must never restart (it would start dockerd) and has no network');
    }
  } else if (at(P.dockerEventsRun) >= 0) {
    v.push('L29: docker events recorded outside analyze, or with dockerd not running');
  }

  // L23: each unit is stopped and reset before systemd-run (a re-run in main must not collide)
  for (const unit of [constants.PROXY_UNIT, constants.DNS_UNIT, ...(recording ? [constants.DOCKER_EVENTS_UNIT] : [])]) {
    before('L23', re(`sudo systemctl stop ${unit}`), re(`sudo systemd-run --unit=${unit}`));
    before('L23', re(`sudo systemctl reset-failed ${unit}`), re(`sudo systemd-run --unit=${unit}`));
  }

  // L24: a command that applies the firewall or sudoers never ignores its exit code, unless the
  // call site checks it itself (CHECKED_IGNORES, each with a test of its failure path)
  for (const e of t) {
    const l = line(e);
    if (e.ignore && FAIL_CLOSED.test(l) && !CHECKED_IGNORES.some(r => r.test(l))) {
      v.push(`L24: ${l} ignores its exit code`);
    }
  }
  return v;
}

/** L22, L25: the post step. */
function postInvariants(t: Entry[]): string[] {
  const v: string[] = [];
  const sudo = t.filter(e => e.argv[0] === 'sudo');
  const read = first(t, P.baselineRead);
  const summary = first(t, P.summary);
  if (read < 0 || summary < 0 || read > summary) v.push('L22: the integrity check must run before the report');
  for (const e of sudo) {
    if (!sudoersAllows(e.argv.slice(1))) v.push(`L22: post step needs sudo outside the restricted sudoers: ${line(e)}`);
  }
  // L25: one comparison - the baseline and each file and chain are read once, so the verdict
  // (fail-on-tampering) and the summary cannot disagree
  const reads = sudo.map(line);
  for (const r of new Set(reads)) {
    if (reads.filter(x => x === r).length > 1) v.push(`L25: the integrity check read ${r} more than once`);
  }
  return v;
}

// ------------------------------------------------------------------ scenarios

const ENFORCE: Scenario = {
  name: 'enforce (defaults)',
  inputs: {
    mode: 'enforce',
    'allowed-domains': 'registry.npmjs.org\n.example.org',
    'http-filter': 'api.github.com:\n  "*": GET, HEAD\n'
  },
  flavour: 'sudo',
  docker: { active: true, dockerUser: true, containers: [] }
};

/** A sudo-config as a workflow writes it, and its lines as the restricted sudoers must hold them. */
const SUDO_CONFIG = '- /usr/bin/apt-get update\n- "/usr/bin/apt-get   install *"\n- /usr/bin/nproc\n';
const SUDO_CONFIG_LINES = ['/usr/bin/apt-get update', '/usr/bin/apt-get install *', '/usr/bin/nproc'];

const SCENARIOS: { s: Scenario; x: Omit<Expect, 'mode' | 'flavour'> }[] = [
  { s: ENFORCE, x: { disableSudo: true, dockerRestart: false, containerRules: true } },
  {
    s: { ...ENFORCE, name: 'analyze (defaults)', inputs: { mode: 'analyze', 'allowed-domains': 'registry.npmjs.org' } },
    x: { disableSudo: true, dockerRestart: true, containerRules: true }
  },
  {
    s: {
      ...ENFORCE,
      name: 'enforce, docker: keep with running service containers',
      inputs: { ...ENFORCE.inputs, docker: 'keep' },
      docker: { active: true, dockerUser: true, containers: CONTAINER_IDS }
    },
    x: { disableSudo: true, dockerRestart: true, containerRules: true }
  },
  {
    s: {
      ...ENFORCE,
      name: 'enforce on sudo-rs, docker not running',
      flavour: 'sudo-rs',
      docker: { active: false, dockerUser: false, containers: [] }
    },
    x: { disableSudo: true, dockerRestart: false, containerRules: false }
  },
  {
    s: {
      ...ENFORCE,
      name: 'enforce, docker: stop, disable-sudo: false',
      inputs: { ...ENFORCE.inputs, docker: 'stop', 'disable-sudo': 'false' }
    },
    x: { disableSudo: false, dockerRestart: false, containerRules: false }
  },
  {
    s: { ...ENFORCE, name: 'enforce, sudo-config', inputs: { ...ENFORCE.inputs, 'sudo-config': SUDO_CONFIG } },
    x: { disableSudo: true, dockerRestart: false, containerRules: true, sudoConfig: SUDO_CONFIG_LINES }
  },
  {
    s: {
      ...ENFORCE,
      name: 'enforce on sudo-rs, sudo-config',
      flavour: 'sudo-rs',
      docker: { active: false, dockerUser: false, containers: [] },
      inputs: { ...ENFORCE.inputs, 'sudo-config': SUDO_CONFIG }
    },
    x: { disableSudo: true, dockerRestart: false, containerRules: false, sudoConfig: SUDO_CONFIG_LINES }
  },
  {
    // analyze evaluates the docker policy, never applies it: docker stays usable, so dockerd
    // still restarts for the CA and the containers get the container rules
    s: {
      ...ENFORCE,
      name: 'analyze, docker: stop with running service containers',
      inputs: { mode: 'analyze', docker: 'stop' },
      docker: { active: true, dockerUser: true, containers: CONTAINER_IDS }
    },
    x: { disableSudo: true, dockerRestart: true, containerRules: true }
  },
  {
    s: { ...ENFORCE, name: 'analyze, docker: remove-group', inputs: { mode: 'analyze', docker: 'remove-group' } },
    x: { disableSudo: true, dockerRestart: true, containerRules: true }
  },
  {
    // nothing to record, and docker events would start dockerd through socket activation
    s: {
      ...ENFORCE,
      name: 'analyze, docker not running',
      inputs: { mode: 'analyze' },
      docker: { active: false, dockerUser: false, containers: [] }
    },
    x: { disableSudo: true, dockerRestart: false, containerRules: false }
  },
  {
    // the one behaviour change: analyze evaluates disable-sudo and sudo-config, never applies them
    s: {
      ...ENFORCE,
      name: 'analyze, disable-sudo: true, sudo-config',
      inputs: { mode: 'analyze', 'disable-sudo': 'true', 'sudo-config': SUDO_CONFIG }
    },
    x: { disableSudo: true, dockerRestart: true, containerRules: true, sudoConfig: SUDO_CONFIG_LINES }
  }
];

beforeAll(() => {
  jest.useFakeTimers({ now: NOW, doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'] });
  jest.spyOn(Math, 'random').mockReturnValue(0.5);
  global.fetch = jest.fn(async (url: string | URL | Request) => {
    mockHost.record({ argv: ['<fetch>', String(url)] });
    return new Response(JSON.stringify(META), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
});

beforeEach(() => {
  process.argv[1] = ACTION_SCRIPT;
  for (const k of Object.keys(process.env)) if (/^(JAVA_HOME|GITHUB_|RUNNER_)/.test(k)) delete process.env[k];
  Object.assign(process.env, {
    JAVA_HOME: JDK,
    JAVA_HOME_17_X64: JDK,
    GITHUB_RUN_ID: '1234567890',
    GITHUB_JOB: 'build',
    GITHUB_ACTION_REF: 'v2.3.0',
    RUNNER_TEMP: '/home/runner/work/_temp'
  });
});

afterAll(() => {
  process.argv[1] = savedArgv;
  process.env = savedEnv;
  jest.useRealTimers();
  jest.restoreAllMocks();
});

describe('setup transcript (runSetup on a recording fake runner)', () => {
  it.each(SCENARIOS)('$s.name', async ({ s, x }) => {
    const h = await setup(s);
    expect(h.failed).toEqual([]);
    expect(setupInvariants(h.transcript, { ...x, mode: h.mode, flavour: s.flavour })).toEqual([]);
    expect(transcriptText(h.transcript)).toMatchSnapshot('transcript');
    expect(writtenFiles(h)).toMatchSnapshot('files');
    expect(h.log.filter(l => /^(warning|error)/.test(l)).map(ts)).toMatchSnapshot('warnings');
    // the sudo log the post step reads: nothing from setup shows up as the workflow's
    expect(h.files.get(SUDO_LOG)).toBeDefined();
  });

  it('enforce: DOCKER-USER missing fails closed before any rule changes', async () => {
    const h = newHost({ ...ENFORCE, docker: { active: true, dockerUser: false, containers: [] } });
    await expect(settle(runSetup(readInputs()))).rejects.toThrow(/DOCKER-USER chain is missing/);
    const t = h.transcript;
    expect(first(t, P.dockerUserProbe)).toBeGreaterThan(-1);
    expect(first(t, P.restore4)).toBe(-1);
    expect(first(t, P.restore6)).toBe(-1);
    expect(first(t, P.jumpDelete)).toBe(-1);
    expect(first(t, P.routeLocalnet)).toBe(-1);
    expect(first(t, P.marker)).toBe(-1);
    expect(first(t, P.sudoersMv)).toBe(-1);
    expect(transcriptText(t)).toMatchSnapshot('transcript');
  });

  it.each([
    ['enforce', ENFORCE.inputs],
    ['analyze', { mode: 'analyze' }]
  ])('%s: ip6tables-restore failing (its exit code is checked, L24)', async (mode, inputs) => {
    const h = newHost({ ...ENFORCE, inputs });
    h.ip6RestoreFails = true;
    const setupRun = settle(runSetup(readInputs()));
    if (mode === 'enforce') {
      await expect(setupRun).rejects.toThrow('ip6tables rules could not be applied');
      // fails before the self-tests, the marker or anything after the firewall
      expect(first(h.transcript, P.curl)).toBe(-1);
      expect(first(h.transcript, P.marker)).toBe(-1);
    } else {
      await setupRun;
      expect(h.log).toContain('warning: ip6tables rules could not be applied');
      expect(first(h.transcript, P.marker)).toBeGreaterThan(-1);
    }
  });

  it('trust: CA in the system store, every JDK and the exported variables', async () => {
    const h = await setup(ENFORCE);
    const t = h.transcript.map(line);
    expect(t).toContain(`sudo install -m 0644 -o root -g root ${CA_CERT_FILE} ${SYSTEM_CA_FILE}`);
    expect(t).toContain(
      `sudo ${JDK}/bin/keytool -importcert -noprompt -keystore ${JDK}/lib/security/cacerts -storepass changeit -alias safer-runner-ca -file ${CA_CERT_FILE}`
    );
    // JAVA_HOME and JAVA_HOME_17_X64 are the same JDK: imported once
    expect(t.filter(l => l.includes('-importcert'))).toHaveLength(1);
    expect(t.filter(l => l.startsWith('<export> '))).toEqual(
      [
        'NODE_EXTRA_CA_CERTS',
        'NODE_USE_SYSTEM_CA',
        'REQUESTS_CA_BUNDLE',
        'PIP_CERT',
        'SSL_CERT_FILE',
        'GIT_SSL_CAINFO',
        'AWS_CA_BUNDLE',
        'CURL_CA_BUNDLE'
      ].map(k => expect.stringMatching(new RegExp(`^<export> ${k}=`)))
    );
    expect(h.files.get(CA_BUNDLE)).toContain(FAKE_CERT);
  });
});

describe('sudo-config in enforce', () => {
  const WITH_CONFIG = SCENARIOS.find(c => c.s.name === 'enforce, sudo-config')!;

  it('the job can run exactly its sudo-config lines as root, and nothing else', async () => {
    const h = await setup(WITH_CONFIG.s);
    const sudo = (cmd: string) => h.exec('sudo', cmd.split(' '), { ignoreReturnCode: true });
    expect(await sudo('apt-get update')).toBe(0);
    expect(await sudo('apt-get install -y jq')).toBe(0);
    expect(await sudo('nproc')).toBe(0);
    // `*` takes one or more further arguments; exact lines take exactly theirs; "" takes none
    expect(await sudo('apt-get install')).toBe(1);
    expect(await sudo('apt-get update -o APT::x=y')).toBe(1);
    expect(await sudo('nproc --all')).toBe(1);
    expect(await sudo('apt-get remove jq')).toBe(1);
    expect(await sudo('cat /etc/shadow')).toBe(1);
    // the action's own read-only checks still work
    expect(await sudo(`-n cat ${VALIDATION_STATE_FILE}`)).toBe(0);
  });

  it('an allowlist visudo rejects fails setup and is never installed (L24)', async () => {
    const h = newHost(WITH_CONFIG.s);
    h.failing = P.visudo;
    await expect(settle(runSetup(readInputs()))).rejects.toThrow(/rejected by visudo/);
    expect(h.sudoRestricted).toBe(false);
    expect(h.files.has('/etc/sudoers.d/runner')).toBe(false);
  });

  it('warns that enforce is ADVISORY, and which entries give root', async () => {
    const h = await setup(WITH_CONFIG.s);
    const warnings = h.log.filter(l => l.startsWith('warning: '));
    expect(warnings).toContainEqual(expect.stringContaining('enforce is ADVISORY in this job: sudo-config keeps 3'));
    expect(warnings).toContainEqual(expect.stringContaining("'/usr/bin/apt-get update' gives the job root"));
  });

  describe('L27 has teeth (mutation check)', () => {
    let base: Entry[];
    const x: Expect = {
      mode: 'enforce',
      flavour: 'sudo',
      disableSudo: true,
      dockerRestart: false,
      containerRules: true,
      sudoConfig: SUDO_CONFIG_LINES
    };
    beforeAll(async () => {
      base = (await setup(WITH_CONFIG.s)).transcript;
      expect(setupInvariants(base, x)).toEqual([]);
    });

    const editSudoers = (t: Entry[], f: (text: string) => string): Entry[] =>
      t.map(e => (line(e) === 'sudo tee /tmp/runner-sudoers.tmp' ? { ...e, input: f(e.input ?? '') } : e));
    const ids = (v: string[]) => Array.from(new Set(v.map(m => m.split(':')[0])));

    it.each([
      [
        'a command with no arguments written bare (any arguments)',
        (s: string) => s.replace('/usr/bin/nproc ""', '/usr/bin/nproc')
      ],
      ['ALL added to the job rules', (s: string) => s.replace('/usr/bin/nproc ""', '/usr/bin/nproc "", ALL')],
      ['the job rules run as any user', (s: string) => s.replace('ALL=(root)', 'ALL=(ALL)')],
      ['a sudo-config line dropped', (s: string) => s.replace('/usr/bin/apt-get update, \\\n    ', '')],
      ['a Defaults line added', (s: string) => `${s}Defaults !requiretty\n`]
    ])('%s', (_what, mutate) => {
      expect(ids(setupInvariants(editSudoers(base, mutate), x))).toContain('L27');
    });
  });
});

/** Run the pre or main step (each starts on import) until it has finished. */
async function runStep(h: FakeHost, entry: './pre' | './main'): Promise<void> {
  const from = h.log.length;
  const done = () =>
    h.log
      .slice(from)
      .some(l =>
        /^(setFailed: |warning: safer-runner setup failed|info: ✅ safer-runner v2 (active|already active))/.test(l)
      );
  jest.isolateModules(() => {
    require(entry);
  });
  for (let i = 0; i < 2000 && !done(); i++) await jest.advanceTimersByTimeAsync(100);
  expect(done()).toBe(true);
}

describe('pre then main: the setup marker', () => {
  const ANALYZE_NO_SUDO: Scenario = {
    ...ENFORCE,
    name: 'analyze, disable-sudo: true',
    inputs: { mode: 'analyze', 'disable-sudo': 'true' }
  };

  it('analyze never removes sudo, even with disable-sudo: true (pre, then main skips)', async () => {
    const h = newHost(ANALYZE_NO_SUDO);
    await runStep(h, './pre');
    expect(h.failed).toEqual([]);
    expect(h.files.has(SETUP_MARKER)).toBe(true);
    expect(h.sudoRestricted).toBe(false);
    expect(h.transcript.some(e => /sudoers\.d\/runner|runner-sudoers/.test(line(e)))).toBe(false);
    await runStep(h, './main');
    expect(h.log).toContain('info: ✅ safer-runner v2 already active (configured in the pre step)');
    expect(h.sudoRestricted).toBe(false);
  });

  it.each([
    ['with disable-sudo: true', ANALYZE_NO_SUDO.inputs],
    ['with nothing set', { mode: 'analyze' }]
  ])(
    'analyze, %s: a failure after the marker is a warning (main will not retry; sudo was never going to change)',
    async (_what, inputs) => {
      const h = newHost({ ...ANALYZE_NO_SUDO, inputs });
      h.failing = P.baselineTee;
      await runStep(h, './pre');
      expect(h.failed).toEqual([]);
      expect(h.sudoRestricted).toBe(false);
      expect(h.log).toContainEqual(expect.stringMatching(/^warning: .*after the setup marker.*will not retry/));
    }
  );

  it('enforce: a failure in the sudo restriction fails the pre step (fail closed)', async () => {
    const h = newHost(ENFORCE);
    h.failing = P.visudo;
    await runStep(h, './pre');
    expect(h.sudoRestricted).toBe(false);
    expect(h.failed).toEqual([expect.stringContaining('safer-runner setup failed in enforce mode')]);
  });

  it('a failure before the marker is retried by main, which fails closed', async () => {
    const h = newHost(ANALYZE_NO_SUDO);
    h.failing = P.updateCa;
    await runStep(h, './pre');
    expect(h.files.has(SETUP_MARKER)).toBe(false);
    expect(h.failed).toEqual([]);
    expect(h.log).toContainEqual(expect.stringContaining('The main step will retry.'));
    await runStep(h, './main');
    expect(h.failed).toEqual([expect.stringContaining('safer-runner setup failed')]);
  });

  it('a failure before the marker that main retries successfully: analyze still leaves sudo as it is', async () => {
    const h = newHost(ANALYZE_NO_SUDO);
    h.failing = P.updateCa;
    await runStep(h, './pre');
    h.failing = null;
    await runStep(h, './main');
    expect(h.failed).toEqual([]);
    expect(h.files.has(SETUP_MARKER)).toBe(true);
    expect(h.sudoRestricted).toBe(false);
  });
});

describe('post step transcript', () => {
  async function jobThenPost(tamper?: (h: FakeHost) => void): Promise<FakeHost> {
    const h = await setup(ENFORCE);
    // the job: a refused name carrying data, and its DNS lookup
    h.append(
      FLOW_LOG,
      JSON.stringify({
        ev: 'tls',
        verdict: 'BLOCK',
        reason: 'sni-not-allowed',
        layer: 'sni',
        sni: `${CANARY}.exfil.example.net`,
        client: '10.1.0.4:51000',
        dst: '203.0.113.9:443'
      }) + '\n'
    );
    h.append(DNS_LOG, `[INFO] 127.0.0.1:41000 BLOCK A ${CANARY}.exfil.example.net. NXDOMAIN\n`);
    tamper?.(h);
    await post(h);
    return h;
  }

  it('enforce: integrity, report', async () => {
    const h = await jobThenPost();
    expect(postInvariants(h.transcript)).toEqual([]);
    expect(h.failed).toEqual([]);
    // nothing deletes the CA key: it is on tmpfs and dies with the VM
    expect(h.files.has(PROXY_CA_KEY_FILE)).toBe(true);
    expect(transcriptText(h.transcript)).toMatchSnapshot('transcript');
    expect(h.summaryText).toContain('🔎 no config change seen (advisory)');
    // setup's own sudo, as logged, is never reported as the workflow's
    expect(h.summaryText).toContain('no workflow sudo');
    // redaction holds in the summary and in the job log
    expect(h.summaryText).toContain('‹redacted›');
    expect(h.summaryText).not.toContain(CANARY);
    expect(h.log.join('\n')).not.toContain(CANARY);
  });

  it('enforce: a changed file fails the job (fail-on-tampering)', async () => {
    const h = await jobThenPost(x => x.files.set('/etc/resolv.conf', 'nameserver 8.8.8.8\n'));
    expect(postInvariants(h.transcript)).toEqual([]);
    expect(h.summaryText).toContain('🚨 config tampered');
    expect(h.failed).toEqual([expect.stringContaining('tampered with')]);
  });

  it('enforce: a changed firewall chain fails the job', async () => {
    const h = await jobThenPost(x => x.iptablesGeneration++);
    expect(h.failed).toEqual([expect.stringContaining('tampered with')]);
  });

  it('enforce: an unreadable baseline counts as not intact', async () => {
    const h = await jobThenPost(x => x.files.delete(VALIDATION_STATE_FILE));
    expect(h.summaryText).toContain('❔ config unverified');
    expect(h.failed).toEqual([expect.stringContaining('could not be verified')]);
  });

  it('enforce: a recorded sudo-config that does not parse back still shows ADVISORY', async () => {
    const h = await setup(SCENARIOS.find(c => c.s.name === 'enforce, sudo-config')!.s);
    const marker = JSON.parse(h.files.get(SETUP_MARKER)!);
    h.files.set(SETUP_MARKER, JSON.stringify({ ...marker, sudoConfig: ['/usr/bin/x a:b', 'not a line'] }));
    await post(h);
    expect(h.summaryText).toContain('⚠️ sudo allowlist (2)');
    expect(h.summaryText).not.toContain('controls applied at setup');
    expect(h.log).toContainEqual(expect.stringMatching(/^warning: Unreadable sudo-config in the setup marker/));
  });

  describe('analyze: the docker policy against the use of docker after setup', () => {
    const STOP = () => SCENARIOS.find(c => c.s.name === 'analyze, docker: stop with running service containers')!.s;
    const SERVICE = CONTAINER_IDS[0];
    const RUN = 'babe' + '0'.repeat(59) + '1';
    /** one line as `docker events --format '{{json .}}'` writes it */
    const ev = (Type: string, Action: string, ID: string, Attributes: Record<string, string> = {}) =>
      JSON.stringify({ status: Action, id: ID, Type, Action, Actor: { ID, Attributes }, scope: 'local', time: 1 }) +
      '\n';
    const healthcheck = [
      ev('container', 'exec_create: /bin/sh -c pg_isready -U postgres', SERVICE, {
        image: 'postgres:16',
        execID: 'e1'
      }),
      ev('container', 'exec_start: /bin/sh -c pg_isready -U postgres', SERVICE, { image: 'postgres:16', execID: 'e1' }),
      ev('container', 'exec_die', SERVICE, { image: 'postgres:16', execID: 'e1', exitCode: '0' }),
      ev('container', 'health_status: healthy', SERVICE, { image: 'postgres:16' })
    ];
    const jobUse = [
      ev('image', 'pull', 'alpine:3.20', { name: 'alpine' }),
      ev('container', 'create', RUN, { image: 'alpine:3.20', name: 'eager_turing' }),
      ev('network', 'connect', 'f00dbabe0001', { container: RUN, name: 'bridge', type: 'bridge' }),
      ev('container', 'start', RUN, { image: 'alpine:3.20', name: 'eager_turing' }),
      ev('container', 'die', RUN, { image: 'alpine:3.20', exitCode: '0' }),
      // a step's own docker exec into the service: its command is never shown
      ev('container', `exec_create: psql -c select '${CANARY}'`, SERVICE, { image: 'postgres:16', execID: 'e2' }),
      ev('image', 'tag', 'sha256:0123', { name: `ghcr.io/acme/app:${CANARY}` }),
      ev('image', 'tag', 'sha256:0456', { name: 'ghcr.io/acme/app:release.k3j9x8q2' })
    ];

    async function analyzeThenPost(events: string[], recorderStopped = false): Promise<FakeHost> {
      const h = await setup(STOP());
      for (const e of events) h.append(constants.DOCKER_EVENTS_LOG, e);
      if (recorderStopped) h.units.delete(constants.DOCKER_EVENTS_UNIT);
      await post(h);
      expect(postInvariants(h.transcript)).toEqual([]);
      expect(h.failed).toEqual([]);
      return h;
    }

    it('the job used docker: what enforce would block, and `docker: keep` with its caveat', async () => {
      const h = await analyzeThenPost([...healthcheck, ...jobUse, ...healthcheck]);
      expect(h.summaryText).toContain('<kbd>7 docker uses would be blocked</kbd>');
      expect(h.summaryText).toContain(
        '**Enforce would block docker, which this job used after setup** (`docker: stop`: 2 container actions, ' +
          '1 exec into a container, 3 image actions, 1 network change; listed under Diagnostics)'
      );
      expect(h.summaryText).toContain('> ```yaml\n> docker: keep\n> ```');
      expect(h.summaryText).toContain('enforce with `docker: keep` is ADVISORY');
      expect(h.summaryText).toContain(
        'Images: `alpine:3.20`, `postgres:16`, `ghcr.io/acme/app:‹redacted›`, `ghcr.io/acme/app:release.‹redacted›`'
      );
      expect(h.summaryText).toContain('1 container already ran at setup (service containers)');
      // the healthcheck is dockerd's own; an exec command, container names: never shown
      expect(h.summaryText).not.toContain('pg_isready');
      expect(h.summaryText).not.toContain('eager_turing');
      for (const out of [h.summaryText, h.log.join('\n')]) {
        expect(out).not.toContain(CANARY);
        expect(out).not.toContain('k3j9x8q2');
      }
      expect(h.log).toContain('info: docker WOULD_BLOCK container x2');
      expect(h.log).toContain('info: docker WOULD_BLOCK exec x1');
      expect(h.summaryText).not.toContain('should run unchanged');
      expect(h.summaryText).not.toMatch(/nothing would be blocked/i);
      expect(h.summaryText).toContain('**No host would be blocked.**');
    });

    it('only the service containers ran: docker: stop would stop them; leave docker unset', async () => {
      const h = await analyzeThenPost([...healthcheck, ...healthcheck]);
      expect(h.summaryText).toContain('<kbd>1 service container would be stopped</kbd>');
      expect(h.summaryText).toContain(
        "**`docker: stop` would stop this job's 1 service container.** Leave `docker` unset"
      );
      expect(h.summaryText).toContain('No use of docker after setup was seen.');
      expect(h.summaryText).not.toContain('docker: keep');
      expect(h.summaryText).not.toContain('docker uses would be blocked');
    });

    it('defaults, a recording that stopped early and saw nothing: no all-clear at the top', async () => {
      const h = await setup(SCENARIOS.find(c => c.s.name === 'analyze (defaults)')!.s);
      h.units.delete(constants.DOCKER_EVENTS_UNIT);
      await post(h);
      expect(h.failed).toEqual([]);
      expect(h.summaryText).toContain('<kbd>⚠️ docker use partly unseen</kbd>');
      expect(h.summaryText).toContain(
        '**No use of docker after setup was seen, but the recording did not cover the whole job**, and enforce ' +
          '(`docker: remove-group`) would block any use it missed.'
      );
      expect(h.summaryText).not.toMatch(/nothing would be blocked/i);
      expect(h.summaryText).not.toContain('should run unchanged');
    });

    it('a recording that stopped early is said to be partial', async () => {
      const h = await analyzeThenPost([], true);
      expect(h.summaryText).toContain('The recording did not cover the whole job');
    });

    it('no docker at all, under the default: nothing to change, and stop would also fit', async () => {
      const h = await setup({
        ...STOP(),
        inputs: { mode: 'analyze' },
        docker: { active: true, dockerUser: true, containers: [] }
      });
      await post(h);
      expect(h.summaryText).toContain('No use of docker after setup was seen. `docker: stop` would also fit.');
      expect(h.summaryText).not.toMatch(/docker use|docker: keep|Enforce would block docker/);
    });
  });

  it('analyze: the sudo the policy (disable-sudo + sudo-config) would block, sudo left as it was', async () => {
    const h = await setup(SCENARIOS.find(c => c.s.name === 'analyze, disable-sudo: true, sudo-config')!.s);
    // the job's own sudo: untouched in analyze, and logged
    for (const c of ['apt-get update', 'apt-get install -y jq', 'apt-get remove -y jq']) {
      expect(await h.exec('sudo', c.split(' '), {})).toBe(0);
    }
    await post(h);
    expect(postInvariants(h.transcript)).toEqual([]);
    expect(h.failed).toEqual([]);
    // update and `install *` are in the sudo-config; remove is not
    expect(h.summaryText).toContain('<kbd>1 sudo command would be blocked</kbd>');
    expect(h.summaryText).toContain('**Enforce would block 1 sudo command this job ran**');
    expect(h.summaryText).toContain(
      'Enforce would block (1):\n\n```console\n$ sudo /usr/bin/apt-get remove -y jq\n```'
    );
    expect(h.log).toContain('info: sudo WOULD_BLOCK /usr/bin/apt-get remove -y jq');
  });

  // the job log is as public as the summary: a credential passed as a sudo argument is in neither
  it.each(['analyze, disable-sudo: true, sudo-config', 'enforce, sudo-config'])(
    '%s: sudo arguments that could be credentials are redacted in the summary and the job log',
    async name => {
      const canary = 'hunter2sudo';
      const h = await setup(SCENARIOS.find(c => c.s.name === name)!.s);
      // commands the fake runner knows; refused in enforce (not in the sudo-config)
      for (const c of [`apt-get -u root -p ${canary} appdb`, `nproc --token=${canary}`]) {
        await h.exec('sudo', c.split(' '), { ignoreReturnCode: true });
      }
      await post(h);
      const lists = name.startsWith('analyze') ? ['sudo (workflow)', 'sudo WOULD_BLOCK'] : ['sudo REFUSED'];
      for (const l of lists) {
        expect(h.log).toContain(`info: ${l} /usr/bin/apt-get -u root -p ‹redacted› appdb`);
        expect(h.log).toContain(`info: ${l} /usr/bin/nproc --token=‹redacted›`);
      }
      expect(h.summaryText).toContain('$ sudo /usr/bin/apt-get -u root -p ‹redacted› appdb');
      expect(h.summaryText).not.toContain(canary);
      expect(h.log.join('\n')).not.toContain(canary);
    }
  );
});

describe('invariants have teeth (mutation check)', () => {
  let base: Entry[];
  const x: Expect = { mode: 'enforce', flavour: 'sudo', disableSudo: true, dockerRestart: true, containerRules: true };

  beforeAll(async () => {
    const h = await setup(SCENARIOS[2].s);
    base = h.transcript;
    expect(setupInvariants(base, x)).toEqual([]);
  });

  function swap(t: Entry[], a: RegExp, b: RegExp): Entry[] {
    const out = [...t];
    const i = first(out, a);
    const j = first(out, b);
    expect(i).toBeGreaterThan(-1);
    expect(j).toBeGreaterThan(-1);
    [out[i], out[j]] = [out[j], out[i]];
    return out;
  }

  function moveBefore(t: Entry[], what: RegExp, anchor: RegExp): Entry[] {
    const out = [...t];
    const [e] = out.splice(first(out, what), 1);
    out.splice(first(out, anchor), 0, e);
    return out;
  }

  function ignoreAt(t: Entry[], what: RegExp): Entry[] {
    const out = [...t];
    const i = first(out, what);
    out[i] = { ...out[i], ignore: true };
    return out;
  }

  const ids = (v: string[]) => Array.from(new Set(v.map(s => s.split(':')[0])));

  it.each([
    [
      'L1',
      'meta fetched after resolv.conf points at the resolver',
      (t: Entry[]) => moveBefore(t, P.resolvWrite, P.meta)
    ],
    ['L8', 'CA generated after the proxy started', (t: Entry[]) => moveBefore(t, P.proxyRun, P.caGenerate)],
    ['L9', 'REDIRECT before the proxy is up', (t: Entry[]) => moveBefore(t, P.restore4, P.proxyRun)],
    ['L10', 'dockerd restarted before the CA is in the store', (t: Entry[]) => swap(t, P.updateCa, P.dockerRestart)],
    ['L11', 'resolv.conf switched before CoreDNS answers', (t: Entry[]) => moveBefore(t, P.resolvWrite, P.dnsRun)],
    [
      'L11',
      'firewall before the resolver points at CoreDNS',
      (t: Entry[]) => moveBefore(t, P.restore4, P.resolvUnlink)
    ],
    ['L12', 'firewall before the dockerd restart', (t: Entry[]) => moveBefore(t, P.restore4, P.dockerRestart)],
    ['L13', 'rules changed before the DOCKER-USER probe', (t: Entry[]) => moveBefore(t, P.dockerUserProbe, P.restore6)],
    ['L15', 'self-tests before the firewall', (t: Entry[]) => moveBefore(t, P.restore6, P.selftestWrite)],
    ['L18', 'baseline before sudo logging', (t: Entry[]) => moveBefore(t, P.loggingClassic, P.selftestWrite)],
    ['L19', 'baseline content written before chmod 0600', (t: Entry[]) => swap(t, P.baselineChmod, P.baselineTee)],
    [
      'L20',
      'a workflow-looking sudo command after logging started',
      (t: Entry[]) => [...t.slice(0, -1), { argv: ['sudo', 'cat', '/etc/shadow'] }, t[t.length - 1]]
    ],
    [
      'L18',
      'baseline written before sudo logging is on',
      (t: Entry[]) => moveBefore(t, P.baselineTouch, P.loggingClassic)
    ],
    ['L21', 'sudo restricted before the baseline', (t: Entry[]) => moveBefore(t, P.sudoersMv, P.baselineTouch)],
    [
      'L21',
      'a privileged step after sudo is restricted',
      (t: Entry[]) => [...t, { argv: ['sudo', 'systemctl', 'restart', 'rsyslog'] }]
    ],
    ['L24', 'iptables-restore with its failure ignored', (t: Entry[]) => ignoreAt(t, P.restore4)],
    ['L24', 'the sudoers move with its failure ignored', (t: Entry[]) => ignoreAt(t, P.sudoersMv)],
    ['L24', 'the sudo-logging move with its failure ignored', (t: Entry[]) => ignoreAt(t, P.loggingClassic)]
  ])('%s: %s', (id, _what, mutate) => {
    const v = setupInvariants(mutate(base), x);
    expect(ids(v)).toContain(id);
  });

  it('L26: analyze changes no sudoers', async () => {
    const analyze = SCENARIOS.find(c => c.s.name === 'analyze, disable-sudo: true, sudo-config')!;
    const t = (await setup(analyze.s)).transcript;
    const ax: Expect = { ...analyze.x, mode: 'analyze', flavour: 'sudo' };
    expect(setupInvariants(t, ax)).toEqual([]);
    const restricted = [...t, { argv: ['sudo', 'mv', '/tmp/runner-sudoers.tmp', '/etc/sudoers.d/runner'] }];
    expect(ids(setupInvariants(restricted, ax))).toContain('L26');
  });

  it.each([
    ['sudo', 'gpasswd', '-d', 'runner', 'docker'],
    ['sudo', 'chmod', '600', '/var/run/docker.sock'],
    ['sudo', 'systemctl', 'stop', 'docker.service'],
    ['sudo', 'systemctl', 'disable', 'docker']
  ])('L28: analyze changes no docker access (%s %s %s ...)', async (...argv) => {
    const analyze = SCENARIOS.find(c => c.s.name === 'analyze, docker: stop with running service containers')!;
    const t = (await setup(analyze.s)).transcript;
    const ax: Expect = { ...analyze.x, mode: 'analyze', flavour: 'sudo' };
    expect(setupInvariants(t, ax)).toEqual([]);
    const marker = first(t, P.marker);
    const changed = [...t.slice(0, marker), { argv }, ...t.slice(marker)];
    expect(ids(setupInvariants(changed, ax))).toEqual(['L28']);
  });

  describe('L29 has teeth (mutation check)', () => {
    const analyze = () => SCENARIOS.find(c => c.s.name === 'analyze, docker: stop with running service containers')!;
    const ax = (): Expect => ({ ...analyze().x, mode: 'analyze', flavour: 'sudo' });

    it.each([
      ['started before the dockerd restart', (t: Entry[]) => moveBefore(t, P.dockerEventsRun, P.dockerRestart)],
      ['started after the setup marker', (t: Entry[]) => moveBefore(t, P.marker, P.dockerEventsRun)],
      [
        'restarted on exit (would start dockerd)',
        (t: Entry[]) =>
          t.map(e =>
            P.dockerEventsRun.test(line(e))
              ? { ...e, argv: e.argv.map(a => (a === 'Restart=no' ? 'Restart=always' : a)) }
              : e
          )
      ],
      ['not started', (t: Entry[]) => t.filter(e => !P.dockerEventsRun.test(line(e)))]
    ])('%s', async (_what, mutate) => {
      const t = (await setup(analyze().s)).transcript;
      expect(setupInvariants(t, ax())).toEqual([]);
      expect(ids(setupInvariants(mutate(t), ax()))).toContain('L29');
    });

    it('recorded in enforce', async () => {
      const t = (await setup(ENFORCE)).transcript;
      const x: Expect = { ...SCENARIOS[0].x, mode: 'enforce', flavour: 'sudo' };
      expect(setupInvariants(t, x)).toEqual([]);
      const marker = first(t, P.marker);
      const recorded = [
        ...t.slice(0, marker),
        { argv: ['sudo', 'systemd-run', `--unit=${constants.DOCKER_EVENTS_UNIT}`] },
        ...t.slice(marker)
      ];
      expect(ids(setupInvariants(recorded, x))).toContain('L29');
    });
  });

  it('L25: the integrity check reads each file once (one comparison)', () => {
    const read: Entry = { argv: ['sudo', 'cat', '/etc/resolv.conf'] };
    const t: Entry[] = [
      { argv: ['sudo', '-n', 'cat', VALIDATION_STATE_FILE] },
      read,
      read,
      { argv: ['<summary.write>'] }
    ];
    expect(ids(postInvariants(t))).toEqual(['L25']);
  });

  it('L22: the post step must not need sudo beyond the restricted sudoers', () => {
    const t: Entry[] = [{ argv: ['sudo', '-n', 'cat', VALIDATION_STATE_FILE] }, { argv: ['sudo', 'iptables', '-F'] }];
    expect(ids(postInvariants(t))).toContain('L22');
  });
});
