import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import {
  FRONT_DOORS,
  MANDATORY_PASSTHROUGH,
  buildPolicyConfig,
  compilePattern,
  expandPattern,
  matchesAny,
  normHost,
  parseAllowedDomains,
  GIT_HOSTS,
  gitPatternKey,
  patternsOverlap,
  validatePathPattern,
  validatePattern
} from './policy';
import { GITHUB_PLATFORM_ENDPOINTS } from './config/github-domains';

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

  it("front-door list is the same as the addon's", () => {
    expect(FRONT_DOORS).toEqual(vectors.front_doors);
    const compiled = FRONT_DOORS.map(compilePattern);
    for (const c of vectors.front_door_hosts as { host: string; expect: boolean }[]) {
      expect([c.host, matchesAny(c.host, compiled)]).toEqual([c.host, c.expect]);
    }
  });
});

describe('expandPattern', () => {
  it('expands .host and leaves everything else alone', () => {
    expect(expandPattern('.example.com')).toEqual(['example.com', '*.example.com']);
    expect(expandPattern(' example.com ')).toEqual(['example.com']);
    expect(expandPattern('*.example.com')).toEqual(['*.example.com']);
    expect(expandPattern('..example.com')).toEqual(['..example.com']);
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
    containerPort: 8081,
    passthroughDomains: '',
    blockRiskySubdomains: true
  };

  it('writes policy.json the addon accepts (proxy/policy_core.py validate_config, fails closed otherwise)', () => {
    const { config } = buildPolicyConfig({
      ...base,
      allowedDomains: 'registry.npmjs.org\n*.actions.githubusercontent.com',
      httpFilter: [
        { host: 'github.com', rules: [{ path: 'myorg/app/git-receive-pack', methods: ['POST'] }] },
        { host: '*.actions.githubusercontent.com', rules: [{ path: '*', methods: ['GET', 'HEAD'] }] }
      ],
      allowGithubPlatform: true
    });
    expect(config.http_filter.platform.length).toBeGreaterThan(0);
    const load = (cfg: unknown) =>
      spawnSync(
        'python3',
        [
          '-I',
          '-c',
          'import json, sys; sys.path.insert(0, sys.argv[1]); import policy_core as pc; ' +
            'c = json.load(sys.stdin); pc.validate_config(c); pc.selftest(pc.Policy.from_config(c))',
          path.join(__dirname, '..', 'proxy')
        ],
        { input: JSON.stringify(cfg), encoding: 'utf8' }
      );
    const run = load(config);
    expect(run.stderr).toBe('');
    expect(run.status).toBe(0);
    // and a writer the addon does not know is refused
    const other = load({ ...config, version: 2 });
    expect(other.status).not.toBe(0);
    expect(other.stderr).toContain('PolicyError');
  });

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

  it('expands the .host shorthand to the apex plus all subdomains', () => {
    const { config, warnings } = buildPolicyConfig({
      ...base,
      allowedDomains: '.docker.io registry.npmjs.org',
      passthroughDomains: '.example.org'
    });
    expect(config.allow).toEqual(expect.arrayContaining(['docker.io', '*.docker.io', 'registry.npmjs.org']));
    expect(config.passthrough).toEqual(expect.arrayContaining(['example.org', '*.example.org']));
    expect(warnings).toEqual([]);
  });

  it('a bare user entry is exact: its subdomains are not allowed', () => {
    const { config } = buildPolicyConfig({ ...base, allowedDomains: 'example.com' });
    const allow = config.allow.map(compilePattern);
    expect(matchesAny('example.com', allow)).toBe(true);
    expect(matchesAny('s3cr3t.example.com', allow)).toBe(false);
  });

  it('the .host shorthand cannot smuggle in a dangerous namespace', () => {
    const { config, warnings } = buildPolicyConfig({ ...base, allowedDomains: '.githubusercontent.com' });
    expect(config.allow.some(p => p.includes('githubusercontent.com'))).toBe(false);
    expect(warnings).toHaveLength(2);
  });

  it('records the mode and flow log path', () => {
    const { config } = buildPolicyConfig({ ...base, mode: 'analyze' });
    expect(config.mode).toBe('analyze');
    expect(config.flow_log).toMatch(/proxy-flows\.jsonl$/);
    expect(config.version).toBe(1);
  });
});

describe('buildPolicyConfig container posture', () => {
  it('writes container_tls and the container listener port', () => {
    const { config } = buildPolicyConfig({
      mode: 'enforce',
      githubDomains: ['github.com'],
      allowedDomains: '',
      passthroughDomains: '',
      blockRiskySubdomains: true,
      containerPort: 18081
    });
    expect(config.container_tls).toBe('sni-only');
    expect(config.container_port).toBe(18081);
  });
});

describe('parseAllowedDomains', () => {
  it('should parse space-separated domains', () => {
    const result = parseAllowedDomains('example.com test.org api.service.io');
    expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
  });

  it('should parse newline-separated domains', () => {
    const result = parseAllowedDomains('example.com\ntest.org\napi.service.io');
    expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
  });

  it('should parse comma-separated domains', () => {
    const result = parseAllowedDomains('example.com,test.org,api.service.io');
    expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
  });

  it('should parse mixed separators (spaces, newlines, commas)', () => {
    const result = parseAllowedDomains('example.com, test.org\napi.service.io another.com');
    expect(result).toEqual(['example.com', 'test.org', 'api.service.io', 'another.com']);
  });

  it('should trim whitespace from domains', () => {
    const result = parseAllowedDomains('  example.com  , test.org\n  api.service.io  ');
    expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
  });

  it('should filter out empty strings', () => {
    const result = parseAllowedDomains('example.com,  ,\n\n,test.org');
    expect(result).toEqual(['example.com', 'test.org']);
  });

  it('should handle empty input', () => {
    expect(parseAllowedDomains('')).toEqual([]);
    expect(parseAllowedDomains('   ')).toEqual([]);
    expect(parseAllowedDomains('\n\n')).toEqual([]);
  });

  it('should handle single domain', () => {
    const result = parseAllowedDomains('example.com');
    expect(result).toEqual(['example.com']);
  });

  it('should handle YAML multiline format', () => {
    const yamlStyle = `example.com
      test.org
      api.service.io`;
    const result = parseAllowedDomains(yamlStyle);
    expect(result).toEqual(['example.com', 'test.org', 'api.service.io']);
  });
});

describe('validatePathPattern', () => {
  it.each([
    ['/twirp/*', 'twirp/*'],
    ['*', '*'],
    ['/', ''],
    ['', ''],
    [' /a/b ', 'a/b']
  ])('%p -> %p', (p, want) => {
    expect(validatePathPattern(p)).toEqual(want);
  });

  it.each(vectors.invalid_path_patterns as string[])('rejects %p', p => {
    expect(() => validatePathPattern(p)).toThrow();
  });
});

describe('patternsOverlap', () => {
  it.each([
    ['github.com', 'github.com', true],
    ['github.com', 'api.github.com', false],
    ['*.github.com', 'api.github.com', true],
    ['*.github.com', 'github.com', false],
    ['run-actions-*-azure-*.actions.githubusercontent.com', '*.actions.githubusercontent.com', true],
    [
      'run-actions-*-azure-*.actions.githubusercontent.com',
      'run-actions-1-azure-eastus.actions.githubusercontent.com',
      true
    ],
    ['productionresultssa*.blob.core.windows.net', 'productionresultssa3.blob.core.windows.net', true],
    ['productionresultssa*.blob.core.windows.net', 'attacker.blob.core.windows.net', false]
  ])('%p ~ %p -> %p', (a, b, want) => {
    expect(patternsOverlap(a, b)).toBe(want);
    expect(patternsOverlap(b, a)).toBe(want);
  });
});

describe('GITHUB_PLATFORM_ENDPOINTS', () => {
  it('is explicit: valid host + path, named methods, no blanket read rule', () => {
    expect(GITHUB_PLATFORM_ENDPOINTS.length).toBeGreaterThan(0);
    for (const e of GITHUB_PLATFORM_ENDPOINTS) {
      expect(() => validatePattern(e.host)).not.toThrow();
      expect(validatePathPattern(e.path)).not.toBe('*');
      expect(e.methods.length).toBeGreaterThan(0);
      expect(e.methods).not.toContain('*');
      for (const m of e.methods) expect(m).toMatch(/^[A-Z]+$/);
    }
  });
});

describe('buildPolicyConfig: http-filter', () => {
  const base = {
    mode: 'enforce' as const,
    githubDomains: [
      'github.com',
      'api.github.com',
      '*.actions.githubusercontent.com',
      'productionresultssa1.blob.core.windows.net'
    ],
    allowedDomains: 'registry.npmjs.org',
    containerPort: 8081,
    passthroughDomains: '',
    blockRiskySubdomains: true
  };
  const rule = (host: string, methods = ['GET', 'HEAD']) => ({ host, rules: [{ path: '*', methods }] });

  it('is empty (and inert) by default', () => {
    const { config, warnings } = buildPolicyConfig(base);
    expect(config.http_filter).toEqual({
      hosts: [],
      allow_github_platform: true,
      platform: [],
      platform_auto_allowed: 0,
      platform_optional: 0
    });
    expect(warnings).toEqual([]);
  });

  it('carries the rules; no platform endpoints for a non-platform host', () => {
    const hosts = [rule('registry.npmjs.org'), rule('github.com', ['*'])];
    const { config, warnings } = buildPolicyConfig({ ...base, httpFilter: hosts });
    expect(config.http_filter.hosts).toEqual(hosts);
    expect(config.http_filter.platform_auto_allowed).toBe(0);
    expect(warnings).toEqual([]);
  });

  it('auto-allows the platform endpoints on a filtered platform host', () => {
    const { config } = buildPolicyConfig({ ...base, httpFilter: [rule('*.actions.githubusercontent.com')] });
    const rr = 'results-receiver.actions.githubusercontent.com';
    const run = 'run-actions-*-azure-*.actions.githubusercontent.com';
    expect(config.http_filter.platform).toEqual([
      { host: rr, path: 'twirp/results.services.receiver.Receiver/*', methods: ['POST'], essential: true },
      { host: rr, path: '_ws/ingest.sock', methods: ['GET'], essential: true },
      { host: run, path: '*/idtoken/*', methods: ['GET'], essential: true },
      { host: run, path: '*/renewjob', methods: ['POST'], essential: true },
      { host: run, path: '*/completejob', methods: ['POST'], essential: true },
      { host: rr, path: 'twirp/*', methods: ['POST'], essential: false }
    ]);
    expect(config.http_filter.platform_auto_allowed).toBe(5);
    expect(config.http_filter.platform_optional).toBe(1);

    // artifact and cache storage never overrides the job's own rules
    const blob = buildPolicyConfig({ ...base, httpFilter: [rule('productionresultssa1.blob.core.windows.net')] });
    expect(blob.config.http_filter.platform.map(e => [e.path, e.essential])).toEqual([
      ['actions-results/*', false],
      ['actions-cache/*', false]
    ]);
    expect(blob.config.http_filter).toMatchObject({ platform_auto_allowed: 0, platform_optional: 2 });
  });

  it('allow-github-platform: false turns them off', () => {
    const { config } = buildPolicyConfig({
      ...base,
      httpFilter: [rule('*.actions.githubusercontent.com')],
      allowGithubPlatform: false
    });
    expect(config.http_filter).toMatchObject({
      allow_github_platform: false,
      platform: [],
      platform_auto_allowed: 0,
      platform_optional: 0
    });
  });

  it('warns when a filtered host is not allowed (the filter is inert)', () => {
    const { warnings } = buildPolicyConfig({ ...base, httpFilter: [rule('pypi.org'), rule('github.com')] });
    expect(warnings).toEqual([
      expect.stringMatching(/'pypi.org' is not in allowed-domains, so this filter has no effect/)
    ]);
  });

  it('warns when a filtered host is passthrough (cannot be path-filtered)', () => {
    const { warnings } = buildPolicyConfig({
      ...base,
      passthroughDomains: 'pinned.example.com',
      httpFilter: [rule('pinned.example.com'), rule('hosted-compute-westus.githubapp.com')]
    });
    expect(warnings).toEqual([
      expect.stringMatching(/'pinned.example.com' matches passthrough-domains entry 'pinned.example.com'/),
      expect.stringMatching(
        /'hosted-compute-westus.githubapp.com' matches passthrough-domains entry 'hosted-compute-\*.githubapp.com'.*cannot be path-filtered/
      )
    ]);
  });
});

describe('git hosts (shared vectors with proxy/policy_core.py)', () => {
  it('has the same git hosts as the addon', () => {
    expect(GIT_HOSTS).toEqual(vectors.git_hosts);
  });

  it.each(vectors.git_pattern_keys as { pattern: string; key: string }[])('$pattern -> $key', ({ pattern, key }) => {
    expect(gitPatternKey(pattern)).toBe(key);
  });
});
