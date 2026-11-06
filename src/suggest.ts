/**
 * Runs the http-filter suggester (proxy/suggest.py) for the report.
 *
 * The suggestion is built in Python, next to the matcher that enforces it, so there is one copy
 * of the path matching and of the path-segment redaction a suggestion needs. This side only
 * passes the allowed requests in and checks that what comes back is safe to print as YAML.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import type { AllowedRequest, HttpFilterSuggestion } from './report';
import { STANDARD_METHODS } from './redact';

/** The system interpreter when there is one: a job's own PATH (setup-python, GITHUB_PATH) can't swap it. */
export function defaultPython(): string {
  return fs.existsSync('/usr/bin/python3') ? '/usr/bin/python3' : 'python3';
}

/** -I: no PYTHON* variables, user site or current directory (the job's workspace) on the path. */
const RUN = 'import sys; sys.path.insert(0, sys.argv[1]); import suggest; suggest.main()';
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
  const run = spawnSync(python, ['-I', '-c', RUN, proxyDir], {
    input: JSON.stringify({ requests }),
    encoding: 'utf8',
    timeout: TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024
  });
  if (run.error) throw run.error;
  // stderr is not passed on: an error message can quote a request path, and the job log is public
  if (run.status !== 0) throw new Error(`suggest.py exited ${run.status ?? run.signal}`);
  let out: unknown;
  try {
    out = JSON.parse(run.stdout);
  } catch {
    throw new Error('suggest.py printed no JSON');
  }
  return parseSuggestion(out);
}
