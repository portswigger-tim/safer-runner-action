import type { ReportContext } from '../../report/section';
import { parseFirewallLog } from './log';
import { report } from './report';

const ENFORCE: ReportContext = { mode: 'enforce', enforce: true };
const ANALYZE: ReportContext = { mode: 'analyze', enforce: false };
const line = (prefix: string, dst: string, dport: string, src = '10.1.0.4', sport = '40000') =>
  `Nov  7 12:00:00 vm kernel: [1.2] ${prefix}: IN= OUT=eth0 SRC=${src} DST=${dst} LEN=60 PROTO=TCP SPT=${sport} DPT=${dport} UID=1001 GID=1001`;

describe('firewall report (its Section)', () => {
  it('nothing outside the proxy: no row', () => {
    expect(report({ events: [] }, ENFORCE).blocked).toEqual([]);
  });

  it("a blocked connection: the log's word, the destination, its likely service and the uid", () => {
    const events = parseFirewallLog(
      [
        line('SaferRunner-Drop', '1.1.1.1', '853', '10.1.0.4', '40001'),
        line('SaferRunner-Drop', '1.1.1.1', '853', '10.1.0.4', '40002')
      ].join('\n')
    );
    expect(report({ events }, ENFORCE).blocked).toEqual([
      { reason: '`Drop`', layer: 'firewall', tries: 2, what: '`1.1.1.1:853` TCP · DNS over TLS · uid 1001' }
    ]);
  });

  it('a resent SYN (analyze lets it through, unanswered) is one try: same source port', () => {
    const resent = Array.from({ length: 5 }, () => line('SaferRunner-Egress', '198.51.100.7', '22')).join('\n');
    expect(report({ events: parseFirewallLog(resent) }, ANALYZE).blocked[0].tries).toBe(1);
  });

  it('analyze: the Egress line, which enforce would block', () => {
    const s = report({ events: parseFirewallLog(line('SaferRunner-Egress', '198.51.100.7', '22')) }, ANALYZE);
    expect(s.blocked[0]).toMatchObject({ reason: '`Egress`', what: '`198.51.100.7:22` TCP · SSH · uid 1001' });
  });

  it("leaves the container chain's lines to the container part", () => {
    const s = report({ events: parseFirewallLog(line('SaferRunner-CDrop', '1.1.1.1', '853', '172.17.0.2')) }, ENFORCE);
    expect(s.blocked).toEqual([]);
  });
});
