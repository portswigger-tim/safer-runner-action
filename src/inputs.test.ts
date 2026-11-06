import * as core from '@actions/core';
import {
  DEFAULT_DNS_SERVERS,
  effectiveFailOnTampering,
  parseDnsServers,
  parseHttpFilter,
  parseMethods,
  readInputs,
  resolveDisableSudo,
  resolveDocker,
  resolveFailOnTampering
} from './inputs';

jest.mock('@actions/core');

describe('resolveDisableSudo (review H2: enforce removes sudo by default)', () => {
  it('defaults ON in enforce mode when disable-sudo is unset', () => {
    expect(resolveDisableSudo('', 'enforce')).toEqual([true, true]);
    expect(resolveDisableSudo('  ', 'enforce')).toEqual([true, true]);
  });

  it('defaults off in analyze mode', () => {
    expect(resolveDisableSudo('', 'analyze')).toEqual([false, true]);
  });

  it('honours an explicit false in enforce (the advisory opt-out) - unset and false differ', () => {
    expect(resolveDisableSudo('false', 'enforce')).toEqual([false, false]);
    expect(resolveDisableSudo('FALSE', 'enforce')).toEqual([false, false]);
  });

  it('honours an explicit true in any mode', () => {
    expect(resolveDisableSudo('true', 'analyze')).toEqual([true, false]);
    expect(resolveDisableSudo('True', 'enforce')).toEqual([true, false]);
  });

  it('rejects anything that is not a YAML boolean', () => {
    expect(() => resolveDisableSudo('yes', 'enforce')).toThrow(/disable-sudo must be true or false/);
    expect(() => resolveDisableSudo('0', 'enforce')).toThrow();
  });
});

describe('resolveDocker (enforce removes docker by default)', () => {
  it('defaults to remove-group in enforce and keep in analyze', () => {
    expect(resolveDocker('', 'enforce')).toEqual(['remove-group', true]);
    expect(resolveDocker('  ', 'enforce')).toEqual(['remove-group', true]);
    expect(resolveDocker('', 'analyze')).toEqual(['keep', true]);
  });

  it('an explicit value always wins, in either mode', () => {
    expect(resolveDocker('keep', 'enforce')).toEqual(['keep', false]);
    expect(resolveDocker('stop', 'enforce')).toEqual(['stop', false]);
    expect(resolveDocker(' Remove-Group ', 'analyze')).toEqual(['remove-group', false]);
    expect(resolveDocker('stop', 'analyze')).toEqual(['stop', false]);
  });

  it('rejects the old boolean spellings and anything else', () => {
    expect(() => resolveDocker('true', 'enforce')).toThrow(/docker must be one of keep, remove-group, stop/);
    expect(() => resolveDocker('false', 'enforce')).toThrow();
    expect(() => resolveDocker('disable', 'enforce')).toThrow();
  });
});

describe('resolveFailOnTampering (mode-aware)', () => {
  it('defaults ON in enforce and off in analyze', () => {
    expect(resolveFailOnTampering('', 'enforce')).toEqual([true, true]);
    expect(resolveFailOnTampering('', 'analyze')).toEqual([false, true]);
  });

  it('an explicit value always wins', () => {
    expect(resolveFailOnTampering('false', 'enforce')).toEqual([false, false]);
    expect(resolveFailOnTampering('true', 'analyze')).toEqual([true, false]);
  });

  it('rejects anything that is not a YAML boolean', () => {
    expect(() => resolveFailOnTampering('on', 'enforce')).toThrow(/fail-on-tampering must be true or false/);
  });

  it('the post step trusts the value setup recorded, and resolves the input only without one', () => {
    expect(effectiveFailOnTampering(false, 'true', 'enforce')).toBe(false);
    expect(effectiveFailOnTampering(true, '', 'analyze')).toBe(true);
    expect(effectiveFailOnTampering(undefined, '', 'enforce')).toBe(true);
    expect(effectiveFailOnTampering(undefined, '', 'analyze')).toBe(false);
  });
});

describe('parseDnsServers', () => {
  it('defaults to Quad9 when empty (never no resolver)', () => {
    expect(parseDnsServers('')).toEqual(['9.9.9.9', '149.112.112.112']);
    expect(parseDnsServers(' \n ,')).toEqual(DEFAULT_DNS_SERVERS);
  });

  it('accepts space, comma and newline separated lists, primary first', () => {
    expect(parseDnsServers('1.1.1.1')).toEqual(['1.1.1.1']);
    expect(parseDnsServers('1.1.1.1, 1.0.0.1\n8.8.8.8 2606:4700:4700::1111')).toEqual([
      '1.1.1.1',
      '1.0.0.1',
      '8.8.8.8',
      '2606:4700:4700::1111'
    ]);
    expect(parseDnsServers('1.1.1.1 1.1.1.1 9.9.9.9')).toEqual(['1.1.1.1', '9.9.9.9']);
  });

  it('rejects anything that is not an IP address', () => {
    expect(() => parseDnsServers('dns.quad9.net')).toThrow(/dns-servers: 'dns.quad9.net' is not an IP address/);
    expect(() => parseDnsServers('9.9.9.9 }')).toThrow();
  });
});

describe('readInputs', () => {
  const inputs = (values: Record<string, string>) =>
    (core.getInput as jest.Mock).mockImplementation((name: string) => values[name] ?? '');

  it('enforce with nothing set: sudo removed, docker remove-group, fail-on-tampering on, Quad9', () => {
    inputs({ mode: 'enforce' });
    expect(readInputs()).toMatchObject({
      mode: 'enforce',
      disableSudo: true,
      disableSudoDefaulted: true,
      docker: 'remove-group',
      dockerDefaulted: true,
      failOnTampering: true,
      dnsServers: ['9.9.9.9', '149.112.112.112'],
      blockRiskySubdomains: true
    });
  });

  it('analyze with nothing set changes nothing on the runner', () => {
    inputs({});
    expect(readInputs()).toMatchObject({
      mode: 'analyze',
      disableSudo: false,
      docker: 'keep',
      failOnTampering: false
    });
  });

  it('has no removed inputs left in its result', () => {
    inputs({ mode: 'enforce' });
    const keys = Object.keys(readInputs());
    for (const gone of [
      'proxyPort',
      'streamLargeBodies',
      'containerTls',
      'sudoConfig',
      'disableDocker',
      'stopDocker'
    ]) {
      expect(keys).not.toContain(gone);
    }
  });
});

describe('parseMethods', () => {
  it.each([
    ['GET, HEAD', ['GET', 'HEAD']],
    ['get,head', ['GET', 'HEAD']],
    ['GET HEAD GET', ['GET', 'HEAD']],
    ['"GET, POST"', ['GET', 'POST']],
    ['[GET, "HEAD"]', ['GET', 'HEAD']],
    ['"*"', ['*']],
    ['*', ['*']],
    ['ALL', ['*']],
    ['all', ['*']],
    ['NONE', []],
    ['', []],
    ['[]', []]
  ])('%p -> %p', (raw, want) => {
    expect(parseMethods(raw)).toEqual(want);
  });

  it('takes JSON lists and null', () => {
    expect(parseMethods(['get', 'HEAD'])).toEqual(['GET', 'HEAD']);
    expect(parseMethods(null)).toEqual([]);
  });

  it.each(['GET, *', 'ALL, POST', 'NONE, GET', 'GET; DROP', '1GET', 'G?T'])('rejects %p', raw => {
    expect(() => parseMethods(raw)).toThrow();
  });
});

describe('parseHttpFilter', () => {
  it('is empty when unset', () => {
    expect(parseHttpFilter('')).toEqual([]);
    expect(parseHttpFilter('  \n ')).toEqual([]);
  });

  it('parses the design example (block form, comments, quoted and bare keys)', () => {
    const raw = [
      'registry.npmjs.org:',
      '  "*": GET, HEAD                               # install yes, npm publish (PUT) no',
      'api.github.com:',
      '  "*": GET, HEAD',
      '# a comment line',
      '',
      'github.com:',
      '  "*": "*"                                     # baseline: allow everything',
      '  "*/git-receive-pack": NONE                   # deny all pushes',
      "  'portswigger-tim/*/git-receive-pack': ALL    # ...except our org",
      '  /v2/sha256:*: GET'
    ].join('\n');
    expect(parseHttpFilter(raw)).toEqual([
      { host: 'registry.npmjs.org', rules: [{ path: '*', methods: ['GET', 'HEAD'] }] },
      { host: 'api.github.com', rules: [{ path: '*', methods: ['GET', 'HEAD'] }] },
      {
        host: 'github.com',
        rules: [
          { path: '*', methods: ['*'] },
          { path: '*/git-receive-pack', methods: [] },
          { path: 'portswigger-tim/*/git-receive-pack', methods: ['*'] },
          { path: 'v2/sha256:*', methods: ['GET'] }
        ]
      }
    ]);
  });

  it('parses the inline form, where a comma continues the methods until the next key', () => {
    const raw = [
      'registry.npmjs.org:   { "*": GET, HEAD }   # npm install yes, npm publish no',
      'example.org: { "*": GET, HEAD, "/upload/*": PUT, POST, "/admin/*": NONE }'
    ].join('\n');
    expect(parseHttpFilter(raw)).toEqual([
      { host: 'registry.npmjs.org', rules: [{ path: '*', methods: ['GET', 'HEAD'] }] },
      {
        host: 'example.org',
        rules: [
          { path: '*', methods: ['GET', 'HEAD'] },
          { path: 'upload/*', methods: ['PUT', 'POST'] },
          { path: 'admin/*', methods: [] }
        ]
      }
    ]);
  });

  it('keeps a uniform base indent (block scalar) and normalises hosts', () => {
    const raw = '    GitHub.com.:\n      "*": get\n    .example.org:\n      "/": GET\n';
    expect(parseHttpFilter(raw)).toEqual([
      { host: 'github.com', rules: [{ path: '*', methods: ['GET'] }] },
      { host: 'example.org', rules: [{ path: '', methods: ['GET'] }] },
      { host: '*.example.org', rules: [{ path: '', methods: ['GET'] }] }
    ]);
  });

  it('accepts JSON (e.g. from toJSON())', () => {
    expect(parseHttpFilter('{"github.com": {"*": "GET, HEAD", "/a/*": ["put"], "b": null}}')).toEqual([
      {
        host: 'github.com',
        rules: [
          { path: '*', methods: ['GET', 'HEAD'] },
          { path: 'a/*', methods: ['PUT'] },
          { path: 'b', methods: [] }
        ]
      }
    ]);
  });

  it.each([
    ['no rules', 'github.com:\n', /no path rules/],
    ['empty inline', 'github.com: {}', /no path rules/],
    ['value instead of rules', 'github.com: GET', /following lines/],
    ['nested list', 'github.com:\n  "*":\n    - GET', /key: value|indentation/],
    ['inconsistent indent', 'github.com:\n  "*": GET\n    "a": GET', /inconsistent indentation/],
    ['dedent below the host level', '  github.com:\n    "*": GET\nother.com:\n  "*": GET', /unexpected indentation/],
    ['rule with no host', '  "*": GET', /following lines/],
    ['tabs', 'github.com:\n\t"*": GET', /tabs/],
    ['bad host', 'not a host:\n  "*": GET', /key: value|domain/],
    ['IP host', '1.2.3.4:\n  "*": GET', /IP literals/],
    ['too-broad host', '*.com:\n  "*": GET', /too broad/],
    ['duplicate host', 'github.com:\n  "*": GET\nGITHUB.COM:\n  "*": GET', /more than once/],
    ['duplicate path', 'github.com:\n  "/a": GET\n  "a": PUT', /duplicate path/],
    ['bad path', 'github.com:\n  "a/**": GET', /\*\*/],
    ['encoded path', 'github.com:\n  "@s%2f*": GET', /invalid path pattern/],
    ['dot segment', 'github.com:\n  "a/../b": GET', /segment/],
    ['bad method', 'github.com:\n  "*": GET, PO ST!', /not an HTTP method/],
    ['bad JSON', '{"github.com": ', /invalid JSON/],
    ['JSON list', '{"github.com": ["GET"]}', /object of path/],
    ['JSON number', '{"github.com": {"*": 1}}', /string or a list/]
  ])('rejects %s', (_name, raw, err) => {
    expect(() => parseHttpFilter(raw)).toThrow(err);
  });
});

describe('path pattern validation (shared vectors with proxy/policy_core.py)', () => {
  const vectors = JSON.parse(
    require('fs').readFileSync(require('path').join(__dirname, '..', 'proxy', 'test-vectors.json'), 'utf8')
  );
  it.each(vectors.invalid_path_patterns as string[])('rejects %p', p => {
    expect(() => parseHttpFilter(JSON.stringify({ 'example.org': { [p]: 'GET' } }))).toThrow();
  });
  it.each(vectors.valid_path_patterns as string[])('accepts %p', p => {
    expect(parseHttpFilter(JSON.stringify({ 'example.org': { [p]: 'GET' } }))).toHaveLength(1);
  });
});

describe('readInputs: http-filter', () => {
  const inputs = (values: Record<string, string>) =>
    (core.getInput as jest.Mock).mockImplementation((name: string) => values[name] ?? '');

  it('defaults: nothing filtered, platform endpoints on', () => {
    inputs({});
    expect(readInputs()).toMatchObject({ httpFilter: [], allowGithubPlatform: true });
  });

  it('parses the filter and the toggle', () => {
    inputs({ 'http-filter': 'api.github.com:\n  "*": GET', 'allow-github-platform': 'false' });
    expect(readInputs()).toMatchObject({
      httpFilter: [{ host: 'api.github.com', rules: [{ path: '*', methods: ['GET'] }] }],
      allowGithubPlatform: false
    });
  });

  it('fails on an invalid filter rather than leaving the host open', () => {
    inputs({ 'http-filter': 'api.github.com:\n  "*": GET, NONE' });
    expect(() => readInputs()).toThrow(/NONE/);
    inputs({ 'allow-github-platform': 'maybe' });
    expect(() => readInputs()).toThrow(/allow-github-platform/);
  });
});
