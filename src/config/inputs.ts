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
import { GIT_HOSTS, expandPattern, gitPatternKey, validatePathPattern, validatePattern } from '../policy';
import type { HttpFilterHost, Mode } from '../policy';
import { isMap, isScalar, isSeq } from 'yaml';
import type { Node, Pair, Scalar, YAMLMap } from 'yaml';
import { strictYaml } from './yaml';
import { parseSudoConfig, type SudoRule } from '../services/sudo/config';

/**
 * What happens to docker access. Docker group membership is root-equivalent (a step can use
 * it to remove the egress controls), so the policy removes it by default.
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
  /** true when disable-sudo was not set (the policy then removes sudo) */
  disableSudoDefaulted: boolean;
  /** sudo-config (parseSudoConfig): command lines the job may run as root; [] = none */
  sudoConfig: SudoRule[];
  /** effective value: see resolveDocker() */
  docker: DockerPolicy;
  /** true when docker was not set (the policy then removes docker access) */
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
 * disable-sudo (review H2): the sudo policy. Unset means remove sudo, in either mode: with sudo
 * any step can switch the egress controls off, so enforce is only a boundary without it. The
 * mode decides whether the policy is applied (enforce) or only evaluated (analyze never
 * changes sudo; it reports what enforce would block and suggests a sudo-config).
 */
export function resolveDisableSudo(raw: string): [boolean, boolean] {
  const v = triState(raw, 'disable-sudo');
  return v === null ? [true, true] : [v, false];
}

/**
 * docker: the docker policy. Unset means remove-group, in either mode (docker is root-equivalent,
 * mirroring disable-sudo). The mode decides whether the policy is applied (enforce) or only
 * evaluated (analyze never changes docker; see planDocker).
 */
export function resolveDocker(raw: string): [DockerPolicy, boolean] {
  const v = (raw || '').trim().toLowerCase();
  if (v === '') return ['remove-group', true];
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

/** One `"path": methods` rule as written, before validation. */
type RawRule = { key: string; value: string | string[] | null; where: string };
type RawHost = { key: string; where: string; rules: RawRule[] };

const METHOD = /^[A-Z][A-Z0-9_-]*$/;

function unquote(s: string): string {
  const t = s.trim();
  if (t.length >= 2 && (t[0] === '"' || t[0] === "'") && t[t.length - 1] === t[0]) return t.slice(1, -1);
  return t;
}

/** A key as written: a host name or a path pattern, never a number or other YAML type. */
function keyText(pair: Pair, where: string): string {
  const k = pair.key;
  if (!isScalar(k)) throw new Error(`${where}: a key must be a host name or a path pattern`);
  // `404:` or `v1.0:` must stay the text the user wrote, not a number
  return typeof k.value === 'string' ? k.value : String(k.source ?? k.value);
}

/** The methods of one rule: a string, a list of strings, or nothing (NONE). */
function methodsValue(node: unknown, where: string): string | string[] | null {
  if (isScalar(node) && (node.value === null || typeof node.value === 'string')) return node.value;
  if (isSeq(node) && node.items.every(i => isScalar(i) && typeof i.value === 'string')) {
    return node.items.map(i => (i as Scalar<string>).value);
  }
  throw new Error(`${where}: methods must be a string or a list of strings`);
}

/** The path rules of one host: a block or a flow (`{ }`) mapping. */
function parseRules(map: YAMLMap, src: string, at: (n: Node | null | undefined) => string): RawRule[] {
  const out: RawRule[] = [];
  let end = 0; // where the previous rule's methods end
  for (const pair of map.items) {
    const key = pair.key as Node | null;
    const where = at(key);
    if (pair.value === null) {
      // `{ "*": GET, HEAD }`: in a flow mapping, a word after a comma with no `:` continues the
      // methods of the rule before it. Only that exact shape: not `? key`, not a first entry.
      const prev = out[out.length - 1];
      const between = src.slice(end, key?.range?.[0] ?? end);
      if (!map.flow || !prev || typeof prev.value !== 'string' || !/^\s*,\s*$/.test(between)) {
        throw new Error(`${where}: expected "path": METHODS`);
      }
      prev.value += `, ${keyText(pair, where)}`;
      end = key?.range?.[1] ?? end;
      continue;
    }
    const text = keyText(pair, where);
    if (out.some(r => r.key === text)) throw new Error(`${where}: path pattern '${text}' is listed more than once`);
    out.push({ key: text, value: methodsValue(pair.value, where), where });
    end = (pair.value as Node).range?.[1] ?? end;
  }
  return out;
}

/**
 * http-filter as YAML (JSON is YAML too), checked against its one shape: host -> { path ->
 * methods }. Anything else fails: duplicate keys and deeper nesting are refused (strictYaml
 * refuses the rest).
 */
function parseFilterYaml(raw: string): RawHost[] {
  // duplicates are refused below, once `{ "*": GET, HEAD, "x": PUT, HEAD }` continuations are merged
  const { doc, at } = strictYaml(raw, 'http-filter', {
    fallback: 'check the indentation; write methods as GET, HEAD or [GET, HEAD], not "GET", HEAD',
    hints: { BAD_ALIAS: 'put a key or a value that starts with * in quotes, e.g. "*": GET' },
    uniqueKeys: false
  });
  if (doc.contents === null) return [];
  if (!isMap(doc.contents)) {
    throw new Error(`${at(doc.contents)}: expected host names, each with "path": METHODS rules`);
  }
  const seen = new Set<string>();
  return doc.contents.items.map(pair => {
    const where = at(pair.key as Node | null);
    const key = keyText(pair, where);
    if (seen.has(key)) throw new Error(`${where}: host '${key}' is listed more than once`);
    seen.add(key);
    const v = pair.value;
    if (isMap(v)) return { key, where, rules: parseRules(v, raw, at) };
    // `host:` with nothing after it: no rules (refused below with a hint)
    if (isScalar(v) && v.value === null) return { key, where, rules: [] };
    throw new Error(`${where}: put the path rules on the following lines, or inline as { "path": METHODS }`);
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
 * Input is YAML or JSON, read by the `yaml` library (parseFilterYaml): host keys; under each,
 * `"path": METHODS` lines or an inline `{ "path": METHODS, ... }`. Host keys are domain patterns
 * as in allowed-domains (`.example.com` shorthand included). The report prints its suggestion
 * with the same library (report.ts httpFilterYaml), so a pasted suggestion reads back as printed.
 * Anything invalid throws: a filter that silently didn't apply would leave the host fully open.
 */
export function parseHttpFilter(raw: string): HttpFilterHost[] {
  const text = (raw || '').trim();
  if (!text) return [];
  // parse the raw text, so that line numbers in errors match the input
  const parsed = parseFilterYaml(raw);
  const out = new Map<string, HttpFilterHost>();
  for (const { key, where, rules } of parsed) {
    if (!rules.length) {
      throw new Error(`${where}: '${key}' has no path rules (write "*": NONE to refuse every request)`);
    }
    const compiled: { path: string; methods: string[]; where: string; key: string }[] = [];
    for (const r of rules) {
      let path: string;
      try {
        path = validatePathPattern(r.key);
      } catch (e) {
        throw new Error(`${r.where}: ${(e as Error).message}`);
      }
      compiled.push({ path, methods: parseMethods(r.value, `${r.where} '${r.key}'`), where: r.where, key: r.key });
    }
    for (const entry of expandPattern(key)) {
      let host: string;
      try {
        host = validatePattern(entry);
      } catch (e) {
        throw new Error(`${where}: ${(e as Error).message}`);
      }
      if (out.has(host)) throw new Error(`${where}: '${host}' is listed more than once`);
      // on a git host, spellings of one repository path are the same pattern (see GIT_HOSTS)
      const identity = GIT_HOSTS.includes(host) ? gitPatternKey : (p: string) => p;
      const seen = new Set<string>();
      for (const r of compiled) {
        const id = identity(r.path);
        if (seen.has(id)) throw new Error(`${r.where}: duplicate path pattern '${r.key}' for '${host}'`);
        seen.add(id);
      }
      out.set(host, { host, rules: compiled.map(({ path, methods }) => ({ path, methods })) });
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
  const [disableSudo, disableSudoDefaulted] = resolveDisableSudo(core.getInput('disable-sudo'));
  const sudoConfig = parseSudoConfig(core.getInput('sudo-config', { trimWhitespace: false }));
  if (sudoConfig.length && !disableSudo) {
    throw new Error('sudo-config has no effect with disable-sudo: false (sudo is kept as it is): remove one of them');
  }
  const [docker, dockerDefaulted] = resolveDocker(core.getInput('docker'));
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
    sudoConfig,
    docker,
    dockerDefaulted,
    failOnTampering,
    httpFilter: parseHttpFilter(core.getInput('http-filter', { trimWhitespace: false })),
    allowGithubPlatform: allowGithubPlatform ?? true
  };
}
