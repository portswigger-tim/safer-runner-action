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
  it('enforce with sudo kept: ADVISORY row and chip', () => {
    const s = report({ usage: usage([]), policy: { rules: [], kept: true, wouldBlock: [] }, retained: true }, ENFORCE);
    expect(s.score[0].verdict).toBe('advisory');
    expect(s.advisory.map(a => a.chip)).toEqual(['⚠️ sudo retained']);
  });

  it('enforce with a sudo-config: ADVISORY as an allowlist', () => {
    const policy = { rules: ['/usr/bin/nproc'], kept: false, wouldBlock: [] };
    const s = report({ usage: usage([]), policy, retained: false }, ENFORCE);
    expect(s.advisory.map(a => a.chip)).toEqual(['⚠️ sudo allowlist (1)']);
  });

  it('enforce with sudo removed: an allowed row, a blocked one when sudo refused something', () => {
    const policy = { rules: [], kept: false, wouldBlock: [] };
    expect(report({ usage: usage([]), policy, retained: false }, ENFORCE).score).toEqual([
      { verdict: 'allowed', area: 'Sudo', text: 'removed from the job' }
    ]);
    const s = report({ usage: usage([], [cmd('/usr/bin/id', '')]), policy, retained: false }, ENFORCE);
    expect(s.score.map(r => r.verdict)).toEqual(['blocked']);
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
    expect(s.score).toEqual([{ verdict: 'would-block', area: 'Sudo', text: '1 command would be blocked' }]);
    expect(s.suggestions).toEqual([
      {
        input: 'sudo-config',
        value: '- /usr/bin/apt-get install -y jq\n',
        advisory: 'any sudo-config makes enforce ADVISORY'
      }
    ]);
    expect(s.notes).toContainEqual('sudo lines not suggested: 1 with arguments that look like a secret');
    expect(s.advisory).toEqual([]);
  });

  it('redacts arguments that could be credentials, in the detail and the job log', () => {
    const c = cmd('/usr/bin/mysql', '-p hunter2xyz');
    const s = report(
      { usage: usage([c]), policy: { rules: [], kept: false, wouldBlock: [c] }, retained: false },
      ANALYZE
    );
    expect(
      s.body + jobLog({ usage: usage([c]), policy: { rules: [], kept: false, wouldBlock: [c] } }).join('\n')
    ).not.toContain('hunter2xyz');
  });

  it('analyze without a sudo log: unknown, never an all-clear', () => {
    expect(report({ retained: false }, ANALYZE).score).toEqual([
      { verdict: 'advisory', area: 'Sudo', text: "no sudo log: the job's use of sudo was not seen" }
    ]);
    expect(report({ retained: false }, ANALYZE).body).toBe('No sudo log was found.\n\n');
  });

  it("puts the action's own sudo under Runner System", () => {
    const s = report(
      { usage: { ran: [], refused: [], internal: [cmd('/usr/bin/cat', '/etc/resolv.conf')] }, retained: false },
      ENFORCE
    );
    expect(s.runnerSystem[0].summary).toBe('Safer Runner ran 1 sudo command');
    expect(s.body).toBe('The job ran no sudo.\n\n');
  });

  it('job log: ran, refused and would-block lines', () => {
    const c = cmd('/usr/bin/apt-get', 'install -y jq');
    expect(jobLog({ usage: usage([c]), policy: { rules: [], kept: false, wouldBlock: [c] } })).toEqual([
      'sudo (workflow) /usr/bin/apt-get install -y jq',
      'sudo WOULD_BLOCK /usr/bin/apt-get install -y jq'
    ]);
  });
});
