/**
 * Runs the suggesters for the report: the http-filter (proxy/suggest.py) and the sudo-config
 * (proxy/sudo_suggest.py).
 *
 * The suggestions are built in Python: the http-filter next to the matcher that enforces it, so
 * there is one copy of the path matching and of the path-segment redaction a suggestion needs;
 * the sudo-config next to it, sharing its encoded-data heuristic. This side only passes the
 * observations in and checks that what comes back is safe to print as YAML.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import type { AllowedRequest } from '../services/mitmproxy/flows';
import type { HttpFilterSuggestion } from '../services/mitmproxy/http-filter';
import type { SudoConfigSuggestion } from '../services/sudo/report';
import { parseSudoLine } from '../services/sudo/config';
import type { SudoCommand } from '../services/sudo/log';
import { STANDARD_METHODS } from './redact';

/** The system interpreter when there is one: a job's own PATH (setup-python, GITHUB_PATH) can't swap it. */
export function defaultPython(): string {
  return fs.existsSync('/usr/bin/python3') ? '/usr/bin/python3' : 'python3';
}

/** -I: no PYTHON* variables, user site or current directory (the job's workspace) on the path. */
const run = (module: string) => `import sys; sys.path.insert(0, sys.argv[1]); import ${module}; ${module}.main()`;
const TIMEOUT_MS = 60_000;

const EMPTY: HttpFilterSuggestion = { hosts: [], requests: 0, rules: 0, specific: 0, coarse: false };
/** what suggest.py can print: well-formed names, templated paths, standard methods */
const HOST = /^[a-z0-9_.-]+$/;
const PATH = /^[A-Za-z0-9._~@+*/-]+$/;

function isCount(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
}

/** The suggestion, or throws when anything in it is not what suggest.py prints. */
export function parseSuggestion(value: unknown): HttpFilterSuggestion {
  const s = value as HttpFilterSuggestion;
  const ok =
    typeof s === 'object' &&
    s !== null &&
    Array.isArray(s.hosts) &&
    isCount(s.requests) &&
    isCount(s.rules) &&
    isCount(s.specific) &&
    typeof s.coarse === 'boolean' &&
    s.hosts.every(
      h =>
        typeof h?.host === 'string' &&
        HOST.test(h.host) &&
        Array.isArray(h.rules) &&
        h.rules.every(
          r =>
            typeof r?.path === 'string' &&
            PATH.test(r.path) &&
            Array.isArray(r.methods) &&
            r.methods.every(m => typeof m === 'string' && STANDARD_METHODS.includes(m))
        )
    );
  if (!ok) throw new Error('unexpected output from suggest.py');
  return {
    hosts: s.hosts.map(h => ({ host: h.host, rules: h.rules.map(r => ({ path: r.path, methods: [...r.methods] })) })),
    requests: s.requests,
    rules: s.rules,
    specific: s.specific,
    coarse: s.coarse
  };
}

/** Run one suggester module in `proxyDir` on this JSON input; its parsed JSON output. */
function runSuggester(module: string, input: unknown, proxyDir: string, python: string): unknown {
  const r = spawnSync(python, ['-I', '-c', run(module), proxyDir], {
    input: JSON.stringify(input),
    encoding: 'utf8',
    timeout: TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024
  });
  if (r.error) throw r.error;
  // stderr is not passed on: an error message can quote a request path or a command line, and the job log is public
  if (r.status !== 0) throw new Error(`${module}.py exited ${r.status ?? r.signal}`);
  try {
    return JSON.parse(r.stdout);
  } catch {
    throw new Error(`${module}.py printed no JSON`);
  }
}

/**
 * The suggested http-filter for these allowed requests, from proxy/suggest.py in `proxyDir`.
 * Throws when it can't be built: the caller reports without a suggestion.
 */
export function suggestHttpFilter(
  requests: AllowedRequest[],
  proxyDir: string,
  python = defaultPython()
): HttpFilterSuggestion {
  if (!requests.length) return { ...EMPTY, hosts: [] };
  return parseSuggestion(runSuggester('suggest', { requests }, proxyDir, python));
}

/**
 * The suggestion, or throws when anything in it is not what sudo_suggest.py prints: exact
 * sudo-config lines (never a `*`) and counts.
 */
export function parseSudoSuggestion(value: unknown): SudoConfigSuggestion {
  const s = value as SudoConfigSuggestion;
  const o = s?.omitted;
  const ok =
    typeof s === 'object' &&
    s !== null &&
    Array.isArray(s.rules) &&
    s.rules.length <= 50 &&
    s.rules.every(r => {
      if (typeof r !== 'string' || r.includes('*')) return false;
      try {
        parseSudoLine(r);
        return true;
      } catch {
        return false;
      }
    }) &&
    typeof o === 'object' &&
    o !== null &&
    [o.secret, o.unrepresentable, o.other_user, o.over_cap].every(isCount);
  if (!ok) throw new Error('unexpected output from sudo_suggest.py');
  return {
    rules: [...s.rules],
    omitted: { secret: o.secret, unrepresentable: o.unrepresentable, other_user: o.other_user, over_cap: o.over_cap }
  };
}

/**
 * The suggested sudo-config for the workflow's own sudo commands, from proxy/sudo_suggest.py in
 * `proxyDir`. Throws when it can't be built: the caller reports without a suggestion.
 */
export function suggestSudoConfig(
  commands: SudoCommand[],
  proxyDir: string,
  python = defaultPython()
): SudoConfigSuggestion {
  const input = commands.map(c => ({
    command: c.command,
    args: c.args,
    targetUser: c.targetUser,
    env: c.env === true
  }));
  return parseSudoSuggestion(runSuggester('sudo_suggest', { commands: input }, proxyDir, python));
}
