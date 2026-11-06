/**
 * v2 action inputs (see action.yaml).
 *
 * Several inputs are mode-aware: action.yaml declares no default for them, so the runner
 * leaves the input empty when the workflow doesn't set it and "unset" can be told apart from
 * an explicit value (getBooleanInput would collapse "unset" and "false"). Unset picks the
 * mode's default; an explicit value always wins. Resolvers return [effective, defaulted].
 */

import * as core from '@actions/core';
import * as net from 'net';
import { expandPattern, validatePathPattern, validatePattern } from './policy';
import type { HttpFilterHost, Mode } from './policy';

/**
 * What happens to docker access. Docker group membership is root-equivalent (a step can use
 * it to remove the egress controls), so enforce removes it by default.
 * - keep: leave docker as it is
 * - remove-group: remove the runner user from the docker group and lock the socket to root
 * - stop: stop and disable the docker daemon
 */
export type DockerPolicy = 'keep' | 'remove-group' | 'stop';
export const DOCKER_POLICIES: DockerPolicy[] = ['keep', 'remove-group', 'stop'];

/** Quad9 (filtering, no logging of client IPs): primary + secondary. */
export const DEFAULT_DNS_SERVERS = ['9.9.9.9', '149.112.112.112'];

export interface Inputs {
  mode: Mode;
  allowedDomains: string;
  passthroughDomains: string;
  blockRiskySubdomains: boolean;
  /** CoreDNS upstreams in order: the first is the primary, never empty */
  dnsServers: string[];
  /** effective value: see resolveDisableSudo() */
  disableSudo: boolean;
  /** true when disable-sudo was not set and the mode decided it */
  disableSudoDefaulted: boolean;
  /** effective value: see resolveDocker() */
  docker: DockerPolicy;
  /** true when docker was not set and the mode decided it */
  dockerDefaulted: boolean;
  /** effective value: see resolveFailOnTampering() */
  failOnTampering: boolean;
  /** parsed http-filter (parseHttpFilter); [] = nothing filtered */
  httpFilter: HttpFilterHost[];
  /** allow-github-platform: built-in platform endpoints on filtered hosts (default on) */
  allowGithubPlatform: boolean;
}

export function parseMode(raw: string): Mode {
  const m = (raw || 'analyze').trim().toLowerCase();
  if (m !== 'analyze' && m !== 'enforce') {
    throw new Error(`mode must be "analyze" or "enforce", got "${raw}"`);
  }
  return m;
}

/** A YAML boolean, or null when unset. */
function triState(raw: string, name: string): boolean | null {
  const v = (raw || '').trim();
  if (v === '') return null;
  if (['true', 'True', 'TRUE'].includes(v)) return true;
  if (['false', 'False', 'FALSE'].includes(v)) return false;
  throw new Error(`${name} must be true or false, got "${raw}"`);
}

/**
 * disable-sudo (review H2). Unset means ON in enforce mode: with sudo any step can switch the
 * egress controls off, so enforce is only a boundary without it. Off in analyze.
 */
export function resolveDisableSudo(raw: string, mode: Mode): [boolean, boolean] {
  const v = triState(raw, 'disable-sudo');
  return v === null ? [mode === 'enforce', true] : [v, false];
}

/**
 * docker. Unset means remove-group in enforce (docker is root-equivalent, mirroring
 * disable-sudo), keep in analyze.
 */
export function resolveDocker(raw: string, mode: Mode): [DockerPolicy, boolean] {
  const v = (raw || '').trim().toLowerCase();
  if (v === '') return [mode === 'enforce' ? 'remove-group' : 'keep', true];
  if ((DOCKER_POLICIES as string[]).includes(v)) return [v as DockerPolicy, false];
  throw new Error(`docker must be one of ${DOCKER_POLICIES.join(', ')}, got "${raw}"`);
}

/**
 * fail-on-tampering. Unset means ON in enforce (a subverted control should fail the job), off
 * in analyze (analyze never breaks a build).
 */
export function resolveFailOnTampering(raw: string, mode: Mode): [boolean, boolean] {
  const v = triState(raw, 'fail-on-tampering');
  return v === null ? [mode === 'enforce', true] : [v, false];
}

/**
 * fail-on-tampering as the post step applies it: the value setup resolved and recorded in the
 * root-owned setup marker (a step cannot change it), else - a marker from an older setup -
 * resolved again from the input.
 */
export function effectiveFailOnTampering(recorded: boolean | undefined, raw: string, mode: Mode): boolean {
  return typeof recorded === 'boolean' ? recorded : resolveFailOnTampering(raw, mode)[0];
}

/**
 * dns-servers: space/comma/newline separated IP addresses, first = primary. Empty falls back
 * to Quad9 so the resolver is never left without an upstream.
 */
export function parseDnsServers(raw: string): string[] {
  const servers = (raw || '').split(/[\s,]+/).filter(Boolean);
  for (const s of servers) {
    if (net.isIP(s) === 0) throw new Error(`dns-servers: '${s}' is not an IP address`);
  }
  return servers.length ? Array.from(new Set(servers)) : [...DEFAULT_DNS_SERVERS];
}

/** One `key: value` pair, before validation. */
type RawPair = { key: string; value: string | string[] | null; where: string };

const METHOD = /^[A-Z][A-Z0-9_-]*$/;

function unquote(s: string): string {
  const t = s.trim();
  if (t.length >= 2 && (t[0] === '"' || t[0] === "'") && t[t.length - 1] === t[0]) return t.slice(1, -1);
  return t;
}

/** Drop a `#` comment (at the start, or after whitespace, outside quotes). */
function stripComment(line: string): string {
  let quote = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = '';
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

/** Split `key: value` (key optionally quoted; the `:` must be followed by space or the end). */
function splitKey(s: string): [string, string] | null {
  const t = s.trim();
  if (t[0] === '"' || t[0] === "'") {
    const end = t.indexOf(t[0], 1);
    if (end < 0) return null;
    const m = /^:(?:\s+|$)/.exec(t.slice(end + 1));
    return m ? [t.slice(1, end), t.slice(end + 1 + m[0].length).trim()] : null;
  }
  const m = /^(\S+?):(?:\s+|$)/.exec(t);
  return m ? [m[1], t.slice(m[0].length).trim()] : null;
}

/** Split on commas outside quotes. */
function splitCommas(s: string): string[] {
  const out: string[] = [];
  let quote = '';
  let cur = '';
  for (const c of s) {
    if (quote) {
      if (c === quote) quote = '';
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === ',') {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  out.push(cur);
  return out;
}

/** `{ "*": GET, HEAD, "x/*": NONE }`: a comma that isn't followed by a new `key:` continues the methods. */
function parseFlowRules(inner: string, where: string): RawPair[] {
  const out: RawPair[] = [];
  for (const token of splitCommas(inner)) {
    if (!token.trim()) continue;
    const kv = splitKey(token);
    if (kv) {
      out.push({ key: kv[0], value: kv[1], where });
    } else if (out.length) {
      out[out.length - 1].value += `, ${token.trim()}`;
    } else {
      throw new Error(`${where}: expected "path": METHODS inside { }`);
    }
  }
  return out;
}

/** The YAML subset http-filter accepts: host keys, each with path rules (block or `{ }`). */
function parseFilterYaml(text: string): { key: string; where: string; rules: RawPair[] }[] {
  const hosts: { key: string; where: string; rules: RawPair[]; inline: boolean; ruleIndent: number }[] = [];
  let hostIndent = -1;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = stripComment(lines[i]).replace(/\s+$/, '');
    if (!line.trim()) continue;
    const where = `http-filter line ${i + 1}`;
    const lead = line.slice(0, line.length - line.trimStart().length);
    if (lead.includes('\t')) throw new Error(`${where}: indent with spaces, not tabs`);
    const indent = lead.length;
    if (hostIndent < 0) hostIndent = indent;
    const kv = splitKey(line);
    if (!kv) throw new Error(`${where}: expected "key: value", got '${line.trim()}'`);
    const current = hosts[hosts.length - 1];
    if (indent === hostIndent) {
      const [key, rest] = kv;
      const host = { key, where, rules: [] as RawPair[], inline: false, ruleIndent: -1 };
      if (rest) {
        if (!rest.startsWith('{') || !rest.endsWith('}')) {
          throw new Error(`${where}: put the path rules on the following lines, or inline as { "path": METHODS }`);
        }
        host.rules = parseFlowRules(rest.slice(1, -1), where);
        host.inline = true;
      }
      hosts.push(host);
    } else if (indent > hostIndent && current && !current.inline) {
      if (current.ruleIndent < 0) current.ruleIndent = indent;
      if (indent !== current.ruleIndent) throw new Error(`${where}: inconsistent indentation`);
      current.rules.push({ key: kv[0], value: kv[1], where });
    } else {
      throw new Error(`${where}: unexpected indentation`);
    }
  }
  return hosts;
}

function parseFilterJson(text: string): { key: string; where: string; rules: RawPair[] }[] {
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    throw new Error(`http-filter: invalid JSON: ${(e as Error).message}`);
  }
  const isMap = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
  if (!isMap(obj)) throw new Error('http-filter: expected an object of host -> { path: methods }');
  return Object.entries(obj).map(([key, rules]) => {
    const where = `http-filter '${key}'`;
    if (!isMap(rules)) throw new Error(`${where}: expected an object of path -> methods`);
    return {
      key,
      where,
      rules: Object.entries(rules).map(([path, value]) => {
        const ok =
          value === null ||
          typeof value === 'string' ||
          (Array.isArray(value) && value.every(m => typeof m === 'string'));
        if (!ok) throw new Error(`${where} '${path}': methods must be a string or a list of strings`);
        return { key: path, value: value as string | string[] | null, where };
      })
    };
  });
}

/**
 * Methods for one path rule: a comma list (optionally in [ ]), `*` or `ALL` for any method,
 * `NONE` or nothing to deny the path. Returns ['*'], [] or upper-case names.
 */
export function parseMethods(value: string | string[] | null, where = 'http-filter'): string[] {
  let v = Array.isArray(value) ? value.join(',') : unquote(value ?? '');
  if (v.startsWith('[') && v.endsWith(']')) v = v.slice(1, -1);
  const tokens = Array.from(
    new Set(
      v
        .split(/[\s,]+/)
        .map(t => unquote(t).toUpperCase())
        .filter(Boolean)
    )
  );
  if (tokens.length === 0 || (tokens.length === 1 && tokens[0] === 'NONE')) return [];
  if (tokens.includes('*') || tokens.includes('ALL')) {
    if (tokens.length !== 1) throw new Error(`${where}: '*' / ALL cannot be combined with other methods`);
    return ['*'];
  }
  if (tokens.includes('NONE')) throw new Error(`${where}: NONE cannot be combined with other methods`);
  const bad = tokens.find(t => !METHOD.test(t));
  if (bad) throw new Error(`${where}: '${bad}' is not an HTTP method`);
  return tokens;
}

/**
 * http-filter (docs/DESIGN-L7-path-method.md): host -> { path pattern -> methods }. Naming a
 * host makes it default-deny; it only ever narrows hosts already in allowed-domains.
 *
 * Input is a small YAML subset (host keys; under each, `"path": METHODS` lines or an inline
 * `{ "path": METHODS, ... }`; quoted or bare keys; `#` comments), or a JSON object. Host keys
 * are domain patterns as in allowed-domains (`.example.com` shorthand included). Anything
 * invalid throws: a filter that silently didn't apply would leave the host fully open.
 */
export function parseHttpFilter(raw: string): HttpFilterHost[] {
  const text = (raw || '').trim();
  if (!text) return [];
  // the YAML form keeps its indentation: the first line's indent is the host level
  const parsed = text.startsWith('{') ? parseFilterJson(text) : parseFilterYaml(raw);
  const out = new Map<string, HttpFilterHost>();
  for (const { key, where, rules } of parsed) {
    if (!rules.length) {
      throw new Error(`${where}: '${key}' has no path rules (write "*": NONE to refuse every request)`);
    }
    const compiled = new Map<string, string[]>();
    for (const r of rules) {
      let path: string;
      try {
        path = validatePathPattern(unquote(r.key));
      } catch (e) {
        throw new Error(`${r.where}: ${(e as Error).message}`);
      }
      if (compiled.has(path)) throw new Error(`${r.where}: duplicate path pattern '${r.key}' for '${key}'`);
      compiled.set(path, parseMethods(r.value, `${r.where} '${r.key}'`));
    }
    for (const entry of expandPattern(unquote(key))) {
      let host: string;
      try {
        host = validatePattern(entry);
      } catch (e) {
        throw new Error(`${where}: ${(e as Error).message}`);
      }
      if (out.has(host)) throw new Error(`${where}: '${host}' is listed more than once`);
      out.set(host, { host, rules: Array.from(compiled, ([path, methods]) => ({ path, methods })) });
    }
  }
  return Array.from(out.values());
}

function bool(name: string): boolean {
  // getBooleanInput throws on an empty value (e.g. when inputs are absent in the pre step on a local action)
  const v = core.getInput(name);
  return v === '' ? false : core.getBooleanInput(name);
}

export function readInputs(): Inputs {
  const mode = parseMode(core.getInput('mode'));
  // core.getInput reads the raw INPUT_<NAME> variable ('' when unset - no action.yaml default)
  const [disableSudo, disableSudoDefaulted] = resolveDisableSudo(core.getInput('disable-sudo'), mode);
  const [docker, dockerDefaulted] = resolveDocker(core.getInput('docker'), mode);
  const [failOnTampering] = resolveFailOnTampering(core.getInput('fail-on-tampering'), mode);
  const allowGithubPlatform = triState(core.getInput('allow-github-platform'), 'allow-github-platform');
  return {
    mode,
    allowedDomains: core.getInput('allowed-domains'),
    passthroughDomains: core.getInput('passthrough-domains'),
    blockRiskySubdomains:
      core.getInput('block-risky-github-subdomains') === '' ? true : bool('block-risky-github-subdomains'),
    dnsServers: parseDnsServers(core.getInput('dns-servers')),
    disableSudo,
    disableSudoDefaulted,
    docker,
    dockerDefaulted,
    failOnTampering,
    httpFilter: parseHttpFilter(core.getInput('http-filter', { trimWhitespace: false })),
    allowGithubPlatform: allowGithubPlatform ?? true
  };
}
