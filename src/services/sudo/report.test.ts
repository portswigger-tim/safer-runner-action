import type { ReportContext } from '../../report/section';
import type { SudoCommand } from './log';
import { jobLog, report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false };
const cmd = (command: string, args: string): SudoCommand => ({
  timestamp: 'Nov  7 12:00:00',
  user: 'runner',
  targetUser: 'root',
  command,
  args
});
const usage = (ran: SudoCommand[], refused: SudoCommand[] = []) => ({ ran, refused, internal: [] });

describe('sudo report (its Section)', () => {
  it('enforce with sudo kept: ADVISORY, and the numbers cell says so', () => {
    const s = report({ usage: usage([]), policy: { rules: [], kept: true, wouldBlock: [] }, retained: true }, ENFORCE);
    expect(s.stat).toBe('⚠️ kept');
    expect(s.advisory.map(a => a.label)).toEqual(['sudo kept']);
  });

  it('enforce with a sudo-config: ADVISORY, with the number of lines', () => {
    const policy = { rules: ['/usr/bin/nproc'], kept: false, wouldBlock: [] };
    const s = report({ usage: usage([]), policy, retained: false }, ENFORCE);
    expect(s.stat).toBe('⚠️ 1 sudo-config line');
    expect(s.advisory.map(a => a.label)).toEqual(['1 sudo-config line']);
  });

  it('enforce with sudo removed: removed, and a blocked row for each command sudo blocked', () => {
    const policy = { rules: [], kept: false, wouldBlock: [] };
    const clean = report({ usage: usage([]), policy, retained: false }, ENFORCE);
    expect([clean.stat, clean.blocked]).toEqual(['removed', []]);
    const id = cmd('/usr/bin/id', '');
    const s = report({ usage: usage([], [id, id]), policy, retained: false }, ENFORCE);
    expect(s.blocked).toEqual([{ reason: '`disable-sudo`', layer: 'sudo', tries: 2, what: '`/usr/bin/id`' }]);
    // as the log reaches the report: de-duplicated, with the times it ran
    const once = report({ usage: usage([], [{ ...id, runs: 3 }]), policy, retained: false }, ENFORCE);
    expect(once.blocked[0].tries).toBe(3);
    expect(s.advisory).toEqual([]);
  });

  it('analyze: what enforce would block is a row, and the suggested sudo-config is ADVISORY', () => {
    const c = cmd('/usr/bin/apt-get', 'install -y jq');
    const policy = {
      rules: [],
      kept: false,
      wouldBlock: [c],
      suggestion: {
        rules: ['/usr/bin/apt-get install -y jq'],
        omitted: { secret: 1, unrepresentable: 0, other_user: 0, over_cap: 0 }
      }
    };
    const s = report({ usage: usage([c]), policy, retained: false }, ANALYZE);
    expect(s.stat).toBe('1');
    expect(s.blocked).toEqual([
      { reason: '`disable-sudo`', layer: 'sudo', tries: 1, what: '`/usr/bin/apt-get install -y jq`' }
    ]);
    expect(s.suggestions).toEqual([
      { input: 'sudo-config', value: '- /usr/bin/apt-get install -y jq\n', advisory: 'ADVISORY' }
    ]);
    expect(s.notes).toContainEqual('sudo lines not suggested: 1 with arguments that look like a secret');
    expect(s.advisory).toEqual([]);
  });

  it('analyze with a sudo-config: the commands it allows are listed as allowed, the rest blocked by it', () => {
    const ok = cmd('/usr/bin/nproc', '');
    const no = cmd('/usr/bin/id', '');
    const policy = { rules: ['/usr/bin/nproc'], kept: false, wouldBlock: [no] };
    const s = report({ usage: usage([ok, no, ok]), policy, retained: false }, ANALYZE);
    expect(s.blocked.map(r => r.reason)).toEqual(['`sudo-config`']);
    expect(s.details).toEqual([
      { summary: 'Sudo, allowed: 1 command · 2 runs', body: expect.stringContaining('| `/usr/bin/nproc` | 2 |') }
    ]);
  });

  it('redacts arguments that could be credentials, in the summary and the job log', () => {
    const c = cmd('/usr/bin/mysql', '-p hunter2xyz');
    const s = report(
      { usage: usage([c]), policy: { rules: [], kept: false, wouldBlock: [c] }, retained: false },
      ANALYZE
    );
    expect(
      JSON.stringify(s) + jobLog({ usage: usage([c]), policy: { rules: [], kept: false, wouldBlock: [c] } }).join('\n')
    ).not.toContain('hunter2xyz');
  });

  it('analyze without a sudo log: not recorded, never 0', () => {
    expect(report({ retained: false }, ANALYZE).stat).toBe('not recorded');
  });

  it("the action's own sudo goes in Safer Runner's part, never as the job's", () => {
    const s = report(
      { usage: { ran: [], refused: [], internal: [cmd('/usr/bin/cat', '/etc/resolv.conf')] }, retained: false },
      ENFORCE
    );
    expect(s.checks).toEqual([{ ok: true, check: 'own sudo', detail: '`/usr/bin/cat /etc/resolv.conf`' }]);
    expect(s.details).toEqual([]);
  });

  it('job log: ran, refused and would-block lines', () => {
    const c = cmd('/usr/bin/apt-get', 'install -y jq');
    expect(jobLog({ usage: usage([c]), policy: { rules: [], kept: false, wouldBlock: [c] } })).toEqual([
      'sudo (workflow) /usr/bin/apt-get install -y jq',
      'sudo WOULD_BLOCK /usr/bin/apt-get install -y jq'
    ]);
  });
});
