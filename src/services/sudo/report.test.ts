import type { ReportContext } from '../../report/section';
import type { SudoCommand } from './log';
import { report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false };
const cmd = (command: string, args: string): SudoCommand => ({
  timestamp: 'Nov  7 12:00:00',
  user: 'runner',
  targetUser: 'root',
  command,
  args
});
const usage = (ran: SudoCommand[]) => ({ ran, refused: [], internal: [] });

describe('sudo report (its Section)', () => {
  it('enforce with sudo kept: ADVISORY, a chip and a WARNING', () => {
    const s = report({ usage: usage([]), policy: { rules: [], kept: true, wouldBlock: [] }, retained: true }, ENFORCE);
    expect(s.advisory).toBe('sudo');
    expect(s.chips).toEqual(['⚠️ sudo retained']);
    expect(s.alerts.map(a => a.kind)).toEqual(['WARNING']);
  });

  it('enforce with a sudo-config: ADVISORY as an allowlist', () => {
    const policy = { rules: ['/usr/bin/nproc'], kept: false, wouldBlock: [] };
    const s = report({ usage: usage([]), policy, retained: false }, ENFORCE);
    expect(s.advisory).toBe('sudo (sudo-config allowlist)');
    expect(s.chips).toEqual(['⚠️ sudo allowlist (1)']);
  });

  it('enforce with sudo removed: no advisory, no alert', () => {
    const s = report(
      { usage: usage([]), policy: { rules: [], kept: false, wouldBlock: [] }, retained: false },
      ENFORCE
    );
    expect([s.advisory, s.chips, s.alerts]).toEqual(['', [], []]);
  });

  it('analyze: what enforce would block is a chip, a quoted IMPORTANT part, blocking, and job-log lines', () => {
    const c = cmd('/usr/bin/apt-get', 'install -y jq');
    const s = report(
      { usage: usage([c]), policy: { rules: [], kept: false, wouldBlock: [c] }, retained: false },
      ANALYZE
    );
    expect(s.blocking).toBe(true);
    expect(s.advisory).toBe('');
    expect(s.chips).toEqual(['1 sudo command would be blocked']);
    expect(s.alerts).toEqual([expect.objectContaining({ kind: 'IMPORTANT', quoted: true })]);
    expect(s.jobLog).toEqual([
      'sudo (workflow) /usr/bin/apt-get install -y jq',
      'sudo WOULD_BLOCK /usr/bin/apt-get install -y jq'
    ]);
    expect(s.diagnostics[0].summary).toBe('workflow ran 1 sudo command · enforce would block 1');
  });

  it('redacts arguments that could be credentials, in the diagnostics and the job log', () => {
    const c = cmd('/usr/bin/mysql', '-p hunter2xyz');
    const s = report(
      { usage: usage([c]), policy: { rules: [], kept: false, wouldBlock: [c] }, retained: false },
      ANALYZE
    );
    expect(s.diagnostics[0].body + s.jobLog.join('\n')).not.toContain('hunter2xyz');
  });

  it('no sudo log: no diagnostic', () => {
    expect(report({ retained: false }, ENFORCE).diagnostics).toEqual([]);
  });
});
