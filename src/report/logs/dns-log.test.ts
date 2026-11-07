import * as fs from 'fs';
import * as path from 'path';
import { parseDnsLog, readRefusedNames, refusedNames } from './dns-log';

const fixture = path.join(__dirname, '__fixtures__', 'coredns.log');

describe('parseDnsLog (CoreDNS log plugin, self-labelled lines)', () => {
  const queries = parseDnsLog(fs.readFileSync(fixture, 'utf8'));

  it('reads only the labelled query lines (no banner, no errors)', () => {
    expect(queries).toHaveLength(8);
  });

  it('parses each field; names lower-cased without the trailing dot', () => {
    expect(queries[0]).toEqual({
      client: '127.0.0.1:41452',
      verdict: 'ALLOW',
      type: 'A',
      name: 'github.com',
      rcode: 'NOERROR'
    });
    expect(queries[3].name).toBe('s3cr3t-agvsbg8.objects.githubusercontent.com');
    expect(queries[3].type).toBe('TXT');
  });

  it('keeps an upstream NXDOMAIN (a typo) apart from a policy refusal', () => {
    expect(queries.find(q => q.name === 'no-such-name.nip.io')?.verdict).toBe('ALLOW');
  });

  it('a query name cannot inject a verdict', () => {
    const forged = parseDnsLog('[INFO] 127.0.0.1:1 ALLOW A x.[INFO].1.BLOCK.A.evil.com. NOERROR upstream=- 0s');
    expect(forged.map(q => q.verdict)).toEqual(['ALLOW']);
  });
});

describe('refusedNames', () => {
  it('returns refused and would-be-refused names once, all query types', () => {
    expect(readRefusedNames(fixture)).toEqual([
      's3cr3t-agvsbg8.objects.githubusercontent.com',
      'example.org',
      'www.example.com'
    ]);
  });

  it('is empty for a missing file', () => {
    expect(readRefusedNames('/nonexistent/dns.log')).toEqual([]);
    expect(refusedNames([])).toEqual([]);
  });
});
