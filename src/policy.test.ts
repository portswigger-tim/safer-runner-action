import * as fs from 'fs';
import * as path from 'path';
import {
  MANDATORY_PASSTHROUGH,
  buildPolicyConfig,
  compilePattern,
  dnsDomainsFor,
  matchesAny,
  normHost,
  validatePattern
} from './policy';

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'proxy', 'test-vectors.json'), 'utf8'));

describe('pattern matching (shared vectors with proxy/policy_core.py)', () => {
  it.each(vectors.match as { pattern: string; host: string; expect: boolean }[])(
    '$pattern vs $host -> $expect',
    ({ pattern, host, expect: want }) => {
      expect(matchesAny(host, [compilePattern(pattern)])).toBe(want);
    }
  );

  it.each(vectors.invalid_patterns as string[])('rejects invalid pattern %p', p => {
    expect(() => validatePattern(p)).toThrow();
  });
});

describe('normHost', () => {
  it('strips port, case and trailing dot', () => {
    expect(normHost('API.GitHub.com.:443')).toBe('api.github.com');
    expect(normHost('[::1]:443')).toBe('::1');
    expect(normHost(undefined)).toBe('');
  });
});

describe('buildPolicyConfig', () => {
  const base = {
    mode: 'enforce' as const,
    githubDomains: ['github.com', 'api.github.com', 'productionresultssa1.blob.core.windows.net'],
    allowedDomains: '',
    passthroughDomains: '',
    blockRiskySubdomains: true
  };

  it('always includes the mandatory passthrough set', () => {
    const { config } = buildPolicyConfig({ ...base, passthroughDomains: 'other.example.com' });
    expect(config.passthrough).toEqual([...MANDATORY_PASSTHROUGH, 'other.example.com']);
  });

  it('does not duplicate the mandatory set when the default input is used', () => {
    const { config } = buildPolicyConfig({ ...base, passthroughDomains: MANDATORY_PASSTHROUGH.join(' ') });
    expect(config.passthrough).toEqual(MANDATORY_PASSTHROUGH);
  });

  it('merges user domains and denies risky GitHub subdomains', () => {
    const { config, warnings } = buildPolicyConfig({ ...base, allowedDomains: 'registry.npmjs.org\n*.pypi.org' });
    expect(config.allow).toEqual(expect.arrayContaining(['github.com', 'registry.npmjs.org', '*.pypi.org']));
    expect(config.deny).toContain('gist.github.com');
    expect(warnings).toEqual([]);
  });

  it('does not deny risky subdomains when disabled', () => {
    expect(buildPolicyConfig({ ...base, blockRiskySubdomains: false }).config.deny).toEqual([]);
  });

  it('drops dangerous, invalid and IP entries with warnings', () => {
    const { config, warnings } = buildPolicyConfig({
      ...base,
      allowedDomains: 'blob.core.windows.net *.blob.core.windows.net 1.2.3.4 *.com ok.example.com'
    });
    expect(config.allow).toContain('ok.example.com');
    expect(config.allow).not.toContain('blob.core.windows.net');
    expect(config.allow).not.toContain('*.blob.core.windows.net');
    expect(warnings).toHaveLength(4);
  });

  it('records the mode and flow log path', () => {
    const { config } = buildPolicyConfig({ ...base, mode: 'analyze' });
    expect(config.mode).toBe('analyze');
    expect(config.flow_log).toMatch(/proxy-flows\.jsonl$/);
    expect(config.version).toBe(1);
  });
});

describe('dnsDomainsFor', () => {
  it('maps wildcard patterns to the suffix dnsmasq can forward', () => {
    expect(dnsDomainsFor(['hosted-compute-*.githubapp.com', '*.pypi.org', 'github.com', 'a.b.example.com'])).toEqual([
      'githubapp.com',
      'pypi.org',
      'github.com',
      'a.b.example.com'
    ]);
  });
});
