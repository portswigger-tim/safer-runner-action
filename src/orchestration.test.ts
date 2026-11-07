/**
 * Orchestration nets: runSetup() and the post step against a recording fake runner.
 *
 * Only EXTERNAL boundaries are faked (@actions/core, @actions/exec, fs, os, dns, net, crypto's
 * randomBytes, fetch, Math.random and the timers), never one of our own modules, so the source
 * can be moved and split freely while these tests keep proving what the runner sees.
 *
 * Each scenario records the ordered transcript of every command, fetch, DNS lookup and exported
 * variable, plus the files setup left behind, and snapshots both. On top of the snapshots, the
 * setup and post-step ordering rules (L1-L24, see setupInvariants) are checked as executable
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
  TEARDOWN_BIN,
  VALIDATION_STATE_FILE
} from './constants';
import { runSetup, SETUP_MARKER } from './setup/run';
import { readInputs } from './config/inputs';
import { classifySudoCommands, type SudoCommand } from './parsers/sudo-parser';
import {
  INTERNAL_SUDO_COMMANDS,
  SUDO_LOGGING_RSYSLOG_FILE,
  SUDO_LOGGING_SUDOERS_FILE,
  getValidationSudoCommands
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
  proxyUp = false;
  dnsUp = false;
  sudoLogging = false;
  sudoRestricted = false;
  /** ip6tables-restore fails (a kernel without ip6tables support) */
  ip6RestoreFails = false;
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
    if (cmd === 'sudo' && args[0] === '--version') {
      r = { code: 0, stdout: this.flavour === 'sudo-rs' ? 'sudo-rs 0.2.13-0ubuntu1.2\n' : 'Sudo version 1.9.15p5\n' };
    } else if (cmd === 'sudo') {
      const a = sudoArgv(args);
      const denied = this.sudoRestricted && !sudoersAllows(args);
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
      case TEARDOWN_BIN:
        this.files.delete(PROXY_CA_KEY_FILE);
        return ok();
      default:
        if (c.endsWith('/bin/keytool')) return ok();
        throw new Error(`fake runner: unhandled command: ${a.join(' ')}`);
    }
  }

  private systemctl(a: string[]): Result {
    const [, verb, ...rest] = a;
    const unit = rest.filter(x => !x.startsWith('-'))[0];
    const dockerUnit = unit === 'docker' || unit === 'docker.service' || unit === 'docker.socket';
    if (verb === 'is-active') return { code: dockerUnit && this.docker.active ? 0 : 3 };
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
  const allowed = new Set(getValidationSudoCommands().map(c => c.replace(/^\/usr\/s?bin\//, '').replace(/ ""$/, '')));
  return allowed.has(sudoArgv(args).join(' '));
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

// ------------------------------------------------------------------ invariants (L1-L24)

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
  teardownWrite: re(`sudo tee ${TEARDOWN_BIN}`),
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
  teardownRun: re(`sudo -n ${TEARDOWN_BIN}`),
  baselineRead: re(`sudo -n cat ${VALIDATION_STATE_FILE}`),
  summary: re('<summary.write>')
};

/** Commands that apply the firewall or sudoers: a silent failure here would leave the job open. */
const FAIL_CLOSED =
  /^sudo (ip6?tables-restore |(tee|visudo -c -f|chmod 0440|chown root:root|mv) \/tmp\/(runner-sudoers|safer-runner-sudo-logging)\.tmp)/;
/**
 * Ignored on purpose because the caller checks the code: applyFirewall throws in enforce when
 * ip6tables-restore fails (tested below); disableSudoForRunner throws when visudo rejects the
 * file (services/sudo/index.test.ts).
 */
const CHECKED_IGNORES = [P.restore6, P.visudo];

interface Expect {
  mode: 'analyze' | 'enforce';
  disableSudo: boolean;
  flavour: 'sudo' | 'sudo-rs';
  dockerRestart: boolean;
  containerRules: boolean;
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
  before('L8', P.teardownWrite, P.marker);
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

  if (x.disableSudo) {
    before('L21', P.baselineTee, P.visudo);
    before('L21', P.visudo, P.sudoersChmod);
    before('L21', P.sudoersChmod, P.sudoersMv);
    before('L21', P.sudoersChown, P.sudoersMv);
    const lastSudo = last(t, /^sudo /);
    if (lastSudo !== at(P.sudoersMv)) v.push('L21: restricting sudo must be the last privileged step');
  } else if (at(P.sudoersMv) >= 0) {
    v.push('L21: sudo restricted although disable-sudo is off');
  }

  // L23: each unit is stopped and reset before systemd-run (a re-run in main must not collide)
  for (const unit of [constants.PROXY_UNIT, constants.DNS_UNIT]) {
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

/** L22: the post step. */
function postInvariants(t: Entry[]): string[] {
  const v: string[] = [];
  const sudo = t.filter(e => e.argv[0] === 'sudo');
  if (!sudo.length || !P.teardownRun.test(line(sudo[0])))
    v.push('L22: the CA key teardown must be the first privileged step');
  const read = first(t, P.baselineRead);
  const summary = first(t, P.summary);
  if (read < 0 || summary < 0 || read > summary) v.push('L22: the integrity check must run before the report');
  for (const e of sudo) {
    if (!sudoersAllows(e.argv.slice(1))) v.push(`L22: post step needs sudo outside the restricted sudoers: ${line(e)}`);
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

const SCENARIOS: { s: Scenario; x: Omit<Expect, 'mode' | 'flavour'> }[] = [
  { s: ENFORCE, x: { disableSudo: true, dockerRestart: false, containerRules: true } },
  {
    s: { ...ENFORCE, name: 'analyze (defaults)', inputs: { mode: 'analyze', 'allowed-domains': 'registry.npmjs.org' } },
    x: { disableSudo: false, dockerRestart: true, containerRules: true }
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

  it('enforce: teardown, integrity, report', async () => {
    const h = await jobThenPost();
    expect(postInvariants(h.transcript)).toEqual([]);
    expect(h.failed).toEqual([]);
    expect(h.files.has(PROXY_CA_KEY_FILE)).toBe(false);
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
    ['L21', 'sudo restricted before the baseline', (t: Entry[]) => moveBefore(t, P.sudoersMv, P.baselineTouch)],
    ['L24', 'iptables-restore with its failure ignored', (t: Entry[]) => ignoreAt(t, P.restore4)],
    ['L24', 'the sudoers move with its failure ignored', (t: Entry[]) => ignoreAt(t, P.sudoersMv)]
  ])('%s: %s', (id, _what, mutate) => {
    const v = setupInvariants(mutate(base), x);
    expect(ids(v)).toContain(id);
  });

  it('L22: the post step must not need sudo beyond the restricted sudoers', () => {
    const t: Entry[] = [{ argv: ['sudo', '-n', TEARDOWN_BIN] }, { argv: ['sudo', 'iptables', '-F'] }];
    expect(ids(postInvariants(t))).toContain('L22');
  });
});
