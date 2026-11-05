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
import type { Mode } from './policy';

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
    failOnTampering
  };
}
