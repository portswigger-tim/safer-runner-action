import * as fs from 'fs';
import * as path from 'path';
import { allowExpr, buildCorefile, patternsExpr } from './corefile-builder';
import { compilePattern, matchesAny, normHost } from '../policy';

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'proxy', 'test-vectors.json'), 'utf8'));

/**
 * Evaluate the subset of expr-lang the builder emits, the way CoreDNS's view plugin does
 * (name() is the lower-cased FQDN with a trailing dot). Translated to JS: `in [...]`,
 * `endsWith`, `matches`, `||`, `&&`, `!(...)`.
 */
function evalExpr(expr: string, host: string): boolean {
  const js = expr
    .replace(/name\(\) in (\[[^\]]*\])/g, '$1.includes(n)')
    .replace(/name\(\) endsWith ('[^']*')/g, 'n.endsWith($1)')
    .replace(/name\(\) matches ('[^']*')/g, 'new RegExp($1).test(n)');
  const n = normHost(host) + '.';
  return new Function('n', `return ${js};`)(n) as boolean;
}

describe('patternsExpr (shared vectors with the proxy matchers)', () => {
  it.each(vectors.match as { pattern: string; host: string; expect: boolean }[])(
    '%p vs %p',
    ({ pattern, host, expect: want }) => {
      // DNS sees names, never ports or empty labels: skip the HTTP-only vectors
      if (!host || host.includes(':')) return;
      expect(evalExpr(patternsExpr([pattern]), host)).toBe(want);
    }
  );

  it('agrees with compilePattern across a mixed allowlist', () => {
    const allow = [
      'github.com',
      '*.github.com',
      'objects.githubusercontent.com',
      '*.actions.githubusercontent.com',
      'hosted-compute-*.githubapp.com',
      'productionresultssa7.blob.core.windows.net'
    ];
    const compiled = allow.map(compilePattern);
    const expr = patternsExpr(allow);
    for (const host of [
      'github.com',
      'api.github.com',
      'a.b.github.com',
      'evilgithub.com',
      'objects.githubusercontent.com',
      's3cr3t.objects.githubusercontent.com',
      'actions.githubusercontent.com',
      'pipelines.actions.githubusercontent.com',
      'hosted-compute-westus2.githubapp.com',
      'x.hosted-compute-a.githubapp.com',
      'productionresultssa7.blob.core.windows.net',
      'productionresultssa70.blob.core.windows.net',
      'GITHUB.COM'
    ]) {
      expect([host, evalExpr(expr, host)]).toEqual([host, matchesAny(host, compiled)]);
    }
  });

  it('batches exact names into one membership test', () => {
    expect(patternsExpr(['a.example.com', 'b.example.com', '*.x.org'])).toBe(
      "name() in ['a.example.com.', 'b.example.com.'] || name() endsWith '.x.org.'"
    );
  });

  it('a glob is one label only and anchored', () => {
    expect(patternsExpr(['pre*.example.com'])).toBe("name() matches '^pre[a-z0-9_-]*[.]example[.]com[.]$'");
  });

  it('an empty set matches nothing', () => {
    expect(patternsExpr([])).toBe('false');
  });

  it.each(["a'b.example.com", 'a\\b.example.com', 'a b.example.com', "x.com' || true || '"])(
    'refuses %p (expr injection)',
    p => {
      expect(() => patternsExpr([p])).toThrow();
    }
  );
});

describe('allowExpr', () => {
  it('subtracts the denylist', () => {
    const expr = allowExpr(['*.github.com', 'github.com'], ['gist.github.com']);
    expect(evalExpr(expr, 'api.github.com')).toBe(true);
    expect(evalExpr(expr, 'gist.github.com')).toBe(false);
    expect(evalExpr(expr, 'github.com')).toBe(true);
  });
});

describe('buildCorefile', () => {
  const base = {
    allow: ['github.com', '*.github.com'],
    deny: ['gist.github.com'],
    upstreams: ['9.9.9.9', '149.112.112.112']
  };

  it('enforce: allow block forwards, catch-all answers NXDOMAIN locally', () => {
    const c = buildCorefile({ ...base, mode: 'enforce' });
    const [allowBlock, denyBlock] = c.split(/\n(?=\.:53 \{)/).slice(-2);
    expect(allowBlock).toContain('bind 127.0.0.1');
    expect(allowBlock).toContain(
      "expr (name() in ['github.com.'] || name() endsWith '.github.com.') && !(name() in ['gist.github.com.'])"
    );
    expect(allowBlock).toContain('forward . 9.9.9.9 149.112.112.112');
    expect(allowBlock).toContain(
      'log . "{remote} ALLOW {type} {name} {rcode} upstream={/forward/upstream} {duration}"'
    );
    expect(allowBlock).toContain('serve_stale');
    expect(denyBlock).toContain('template ANY ANY');
    expect(denyBlock).toContain('rcode NXDOMAIN');
    expect(denyBlock).toContain('log . "{remote} BLOCK {type} {name} {rcode}"');
    expect(denyBlock).not.toContain('forward');
    expect(denyBlock).not.toContain('view');
  });

  it('analyze: both blocks forward; the second labels what enforce would refuse', () => {
    const c = buildCorefile({ ...base, mode: 'analyze' });
    expect(c.match(/forward \. 9\.9\.9\.9 149\.112\.112\.112/g)).toHaveLength(2);
    expect(c).toContain('WOULD_BLOCK');
    expect(c).not.toContain('NXDOMAIN');
  });

  it('honours a single custom upstream', () => {
    expect(buildCorefile({ ...base, mode: 'enforce', upstreams: ['1.1.1.1'] })).toContain('forward . 1.1.1.1\n');
  });

  it('refuses a missing or malformed upstream', () => {
    expect(() => buildCorefile({ ...base, mode: 'enforce', upstreams: [] })).toThrow();
    expect(() => buildCorefile({ ...base, mode: 'enforce', upstreams: ['9.9.9.9 }\nimport x'] })).toThrow();
  });

  it('matches the Corefile snapshot', () => {
    expect(buildCorefile({ ...base, mode: 'enforce' })).toMatchSnapshot();
  });
});
