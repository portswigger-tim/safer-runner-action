import type { ReportContext } from '../../report/section';
import { parseFirewallLog } from './log';
import { report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false };
const line = (prefix: string, dst: string, dport: string, src = '10.1.0.4') =>
  `Nov  7 12:00:00 vm kernel: [1.2] ${prefix}: IN= OUT=eth0 SRC=${src} DST=${dst} LEN=60 PROTO=TCP SPT=4 DPT=${dport} UID=1001 GID=1001`;

describe('firewall report (its Section)', () => {
  it('nothing outside the proxy: no scorecard row; Runner System says so', () => {
    const s = report({ events: [] }, ENFORCE);
    expect(s.score).toEqual([]);
    expect(s.runnerSystem).toEqual([{ summary: 'nothing outside the proxy', body: '' }]);
  });

  it('a rejected connection is a blocked row naming the port', () => {
    const s = report({ events: parseFirewallLog(line('SaferRunner-Drop', '1.1.1.1', '853')) }, ENFORCE);
    expect(s.score).toEqual([
      {
        verdict: 'blocked',
        area: 'Network',
        text: '1 connection outside the proxy rejected (DNS-over-TLS to `1.1.1.1:853`)'
      }
    ]);
  });

  it('analyze: a connection outside the proxy would be rejected', () => {
    const s = report({ events: parseFirewallLog(line('SaferRunner-Egress', '198.51.100.7', '22')) }, ANALYZE);
    expect(s.score[0]).toMatchObject({ verdict: 'would-block', text: expect.stringContaining('would be rejected') });
  });

  it("leaves the container chain's lines to the container part", () => {
    const s = report({ events: parseFirewallLog(line('SaferRunner-CDrop', '1.1.1.1', '853', '172.17.0.2')) }, ENFORCE);
    expect(s.score).toEqual([]);
  });
});
