import * as path from 'path';
import { parseSuggestion, suggestHttpFilter } from './suggest';

const PROXY_DIR = path.join(__dirname, '..', 'proxy');
const ok = {
  hosts: [{ host: 'github.com', rules: [{ path: 'myorg/app/git-receive-pack', methods: ['POST'] }] }],
  requests: 1,
  rules: 1,
  specific: 1,
  coarse: false
};

describe('suggestHttpFilter', () => {
  it('runs proxy/suggest.py on the allowed requests', () => {
    expect(
      suggestHttpFilter([{ host: 'GitHub.com', method: 'post', path: '/MyOrg/App.git/git-receive-pack' }], PROXY_DIR)
    ).toEqual(ok);
  });

  it('starts no interpreter when there is nothing to suggest from', () => {
    expect(suggestHttpFilter([], PROXY_DIR, '/nonexistent/python3')).toEqual({
      hosts: [],
      requests: 0,
      rules: 0,
      specific: 0,
      coarse: false
    });
  });

  it('throws when the suggester cannot run, without passing its output on', () => {
    const r = [{ host: 'pypi.org', method: 'GET', path: '/simple/' }];
    expect(() => suggestHttpFilter(r, PROXY_DIR, '/nonexistent/python3')).toThrow();
    expect(() => suggestHttpFilter(r, path.join(__dirname, 'no-such-dir'))).toThrow(/^suggest\.py exited 1$/);
  });
});

describe('parseSuggestion', () => {
  it('accepts what suggest.py prints', () => {
    expect(parseSuggestion(JSON.parse(JSON.stringify(ok)))).toEqual(ok);
    const root = { ...ok, hosts: [{ host: 'uploads.example.com', rules: [{ path: '/', methods: [] }] }] };
    expect(parseSuggestion(root)).toEqual(root);
  });

  it('refuses anything that is not safe to print as YAML', () => {
    const rule = (r: object) => ({
      ...ok,
      hosts: [{ host: 'github.com', rules: [{ ...ok.hosts[0].rules[0], ...r }] }]
    });
    for (const bad of [
      null,
      [],
      { ...ok, coarse: 'no' },
      { ...ok, rules: -1 },
      { ...ok, requests: 1.5 },
      { ...ok, hosts: [{ host: 'evil.example.com"\n  x', rules: [] }] },
      { ...ok, hosts: [{ host: 'github.com' }] },
      rule({ path: 'a"b' }),
      rule({ path: 'a\nb' }),
      rule({ path: 'a: b' }),
      rule({ path: '' }),
      rule({ methods: ['PROPFIND'] }),
      rule({ methods: 'POST' }),
      rule({ methods: [1] })
    ]) {
      expect(() => parseSuggestion(bad)).toThrow('unexpected output from suggest.py');
    }
  });
});
