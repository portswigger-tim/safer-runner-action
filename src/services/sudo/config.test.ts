import * as fs from 'fs';
import * as path from 'path';
import {
  evaluateSudo,
  parseSudoConfig,
  parseSudoLine,
  ruleAllows,
  ruleText,
  sudoConfigWarnings,
  type SudoRule
} from './config';

/** proxy/test-vectors.json "sudo": also run by proxy/sudo_suggest_test.py */
const VECTORS = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', '..', 'proxy', 'test-vectors.json'), 'utf8')
).sudo as {
  valid: { line: string; path: string; args: string[]; anyRest: boolean }[];
  invalid: string[];
  match: { rule: string; command: string; args: string; allowed: boolean }[];
};

describe('sudo-config command lines (shared vectors)', () => {
  it.each(VECTORS.valid.map(v => [v.line, v] as const))('accepts %p', (line, v) => {
    expect(parseSudoLine(line)).toEqual({ path: v.path, args: v.args, anyRest: v.anyRest });
  });

  it.each(VECTORS.invalid)('refuses %p', line => {
    expect(() => parseSudoLine(line)).toThrow();
  });

  it.each(VECTORS.match.map(m => [m.rule, `${m.command} ${m.args}`.trim(), m] as const))(
    '%p allows %p: as in the vectors',
    (_rule, _cmd, m) => {
      expect(ruleAllows(parseSudoLine(m.rule), m.command, m.args)).toBe(m.allowed);
    }
  );

  it('ruleText is the line as sudoers gets it', () => {
    expect(ruleText(parseSudoLine('  /usr/bin/apt-get   install  * '))).toBe('/usr/bin/apt-get install *');
  });
});

describe('parseSudoConfig', () => {
  it.each([
    ['', []],
    ['   \n', []],
    ['[]', []],
    ['~', []]
  ])('%p is no rules', (raw, out) => {
    expect(parseSudoConfig(raw)).toEqual(out);
  });

  it('reads a YAML list, in order', () => {
    expect(parseSudoConfig('- /usr/bin/apt-get update\n- "/usr/sbin/service nginx restart"\n').map(ruleText)).toEqual([
      '/usr/bin/apt-get update',
      '/usr/sbin/service nginx restart'
    ]);
    expect(parseSudoConfig('["/usr/bin/nproc"]').map(ruleText)).toEqual(['/usr/bin/nproc']);
  });

  it.each([
    ['a map', '/usr/bin/apt-get: update', /line 1: expected a list of command lines.*v1 sudo-config format/],
    ['a scalar', '/usr/bin/apt-get update', /expected a list of command lines/],
    ['a nested list', '- - /usr/bin/nproc', /line 1: each entry must be one command line/],
    ['a number', '- 42', /each entry must be one command line/],
    ['an empty item', '- /usr/bin/nproc\n-\n', /line 2: each entry must be one command line/],
    ['a map item', '- path: /usr/bin/nproc', /each entry must be one command line/],
    ['a duplicate', '- /usr/bin/nproc\n- "/usr/bin/nproc  "', /line 2: '\/usr\/bin\/nproc' is listed more than once/],
    ['an anchor', '- &a /usr/bin/nproc\n- *a', /anchors .* are not allowed|starts with its absolute path/],
    ['a tag', '- !!str /usr/bin/nproc', /tags \(!\) are not allowed/],
    ['a document marker', '---\n- /usr/bin/nproc', /document markers/],
    ['a bad line', '- /usr/bin/nproc\n- /usr/bin/x a:b', /line 2: '\/usr\/bin\/x a:b' .*unsupported character/],
    ['a tab indent', '-   /usr/bin/nproc\n\t- /usr/bin/id', /sudo-config line 2/]
  ])('refuses %s', (_what, raw, err) => {
    expect(() => parseSudoConfig(raw)).toThrow(err);
  });

  it('caps the number of rules', () => {
    const many = Array.from({ length: 101 }, (_, i) => `- /usr/bin/x${i}`).join('\n');
    expect(() => parseSudoConfig(many)).toThrow(/at most 100 command lines/);
  });

  it('only parseSudoConfig makes a rule (a compile-time check)', () => {
    // @ts-expect-error - a plain object is not a SudoRule
    const forged: SudoRule = { path: '/bin/sh', args: [], anyRest: false };
    expect(forged).toBeDefined();
  });
});

describe('sudoConfigWarnings', () => {
  it('warns on root-equivalent commands and on a trailing *', () => {
    expect(
      sudoConfigWarnings(
        parseSudoConfig('- /usr/bin/bash -c true\n- /usr/bin/apt-get install *\n- /usr/sbin/service nginx restart')
      )
    ).toEqual([
      "sudo-config: '/usr/bin/bash -c true' gives the job root (bash can run or write anything), so sudo can remove the egress controls",
      "sudo-config: '/usr/bin/apt-get install *' gives the job root (apt-get can run or write anything), so sudo can remove the egress controls"
    ]);
    expect(sudoConfigWarnings(parseSudoConfig('- /usr/local/bin/tool sync *'))).toEqual([
      "sudo-config: '/usr/local/bin/tool sync *' allows any further arguments, including options"
    ]);
    expect(sudoConfigWarnings(parseSudoConfig('- /usr/sbin/service nginx restart'))).toEqual([]);
  });
});

describe('evaluateSudo (analyze: what enforce would block)', () => {
  const ran = (command: string, args: string, targetUser = 'root') => ({
    timestamp: '',
    user: 'runner',
    targetUser,
    command,
    args
  });
  const RAN = [
    ran('/usr/bin/apt-get', 'update'),
    ran('/usr/bin/apt-get', 'install -y jq'),
    ran('/usr/bin/apt-get', 'install'),
    ran('/usr/bin/psql', '-c select', 'postgres')
  ];
  const rules = parseSudoConfig('- /usr/bin/apt-get update\n- /usr/bin/apt-get install *\n- /usr/bin/psql -c select');

  it('blocks what the rules do not allow, and anything as another user (rules run as root)', () => {
    const { allowed, wouldBlock } = evaluateSudo(rules, false, RAN);
    expect(allowed).toEqual(RAN.slice(0, 2));
    expect(wouldBlock).toEqual(RAN.slice(2));
  });

  it('no rules: every workflow sudo command would be blocked', () => {
    expect(evaluateSudo([], false, RAN).wouldBlock).toEqual(RAN);
  });

  it('disable-sudo: false keeps sudo: nothing would be blocked', () => {
    expect(evaluateSudo([], true, RAN)).toEqual({ allowed: RAN, wouldBlock: [] });
  });
});
