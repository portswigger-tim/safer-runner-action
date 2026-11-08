import type { ReportContext } from '../../report/section';
import { parseFirewallLog } from './log';
import { report } from './report';

const CTX: ReportContext = { mode: 'enforce', enforce: true };
const line = (prefix: string, dst: string, dport: string, src = '10.1.0.4') =>
  `Nov  7 12:00:00 vm kernel: [1.2] ${prefix}: IN= OUT=eth0 SRC=${src} DST=${dst} LEN=60 PROTO=TCP SPT=4 DPT=${dport} UID=1001 GID=1001`;

describe('firewall report (its Section)', () => {
  it('nothing outside the proxy: not blocking, one diagnostic that says so', () => {
    const s = report({ events: [] }, CTX);
    expect(s.blocking).toBe(false);
    expect(s.score).toEqual([]);
    expect(s.diagnostics).toEqual([{ summary: 'nothing bypassed the proxy', body: '' }]);
  });

  it('a rejected connection is blocking, with a scorecard row naming the port', () => {
    const s = report({ events: parseFirewallLog(line('SaferRunner-Drop', '1.1.1.1', '853')) }, CTX);
    expect(s.blocking).toBe(true);
    expect(s.score).toEqual([['🧱 **Outside the proxy**', '1 rejected (DNS-over-TLS to `1.1.1.1:853`)']]);
    expect(s.diagnostics[0].summary).toBe('1 non-proxy destination rejected');
  });

  it("leaves the container chain's lines to the container part", () => {
    const s = report({ events: parseFirewallLog(line('SaferRunner-CDrop', '1.1.1.1', '853', '172.17.0.2')) }, CTX);
    expect(s.blocking).toBe(false);
  });
});
