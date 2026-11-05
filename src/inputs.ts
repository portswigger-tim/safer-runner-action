/**
 * v2 action inputs (see action.yaml).
 */

import * as core from '@actions/core';
import type { ContainerTls, Mode } from './policy';

export interface Inputs {
  mode: Mode;
  allowedDomains: string;
  passthroughDomains: string;
  blockRiskySubdomains: boolean;
  primaryDnsServer: string;
  /** '' disables the secondary server */
  secondaryDnsServer: string;
  /** effective value: see resolveDisableSudo() */
  disableSudo: boolean;
  /** true when disable-sudo was not set and the mode decided it */
  disableSudoDefaulted: boolean;
  sudoConfig: string;
  /** effective value: see resolveDisableDocker() (unset means ON in enforce) */
  disableDocker: boolean;
  /** true when disable-docker was not set and the mode decided it */
  disableDockerDefaulted: boolean;
  stopDocker: boolean;
  failOnTampering: boolean;
  /** host listener (containers use proxyPort + 1); null = pick free ports at setup */
  proxyPort: number | null;
  streamLargeBodies: string;
  /** effective container TLS posture (see parseContainerTls) */
  containerTls: ContainerTls;
  /** set when the requested posture is not available and was replaced */
  containerTlsWarning: string;
}

export function parseMode(raw: string): Mode {
  const m = (raw || 'analyze').trim().toLowerCase();
  if (m !== 'analyze' && m !== 'enforce') {
    throw new Error(`mode must be "analyze" or "enforce", got "${raw}"`);
  }
  return m;
}

/** proxy-port: an explicit override, or null (unset) to allocate free ports at setup. */
export function parsePort(raw: string): number | null {
  if ((raw || '').trim() === '') return null;
  const n = Number(raw.trim());
  // the container listener is proxy-port + 1
  if (!Number.isInteger(n) || n < 1024 || n > 65534) {
    throw new Error(`proxy-port must be an integer between 1024 and 65534, got "${raw}"`);
  }
  return n;
}

/**
 * container-tls: `sni-only` (default) or `intercept`. `intercept` needs the CA inside every
 * container, which only the OCI runtime shim can provide; that is not built yet (P3), so it
 * is accepted but treated as `sni-only` with a warning. Returns [effective, warning].
 */
export function parseContainerTls(raw: string): [ContainerTls, string] {
  const v = (raw || 'sni-only').trim().toLowerCase();
  if (v === 'sni-only') return ['sni-only', ''];
  if (v === 'intercept') {
    return [
      'sni-only',
      'container-tls: intercept is not yet implemented (it needs the CA injected into every container); ' +
        'treated as sni-only - container HTTPS to allowlisted hosts is checked by SNI, not decrypted.'
    ];
  }
  throw new Error(`container-tls must be "sni-only" or "intercept", got "${raw}"`);
}

export function parseSize(raw: string): string {
  const s = (raw || '1m').trim().toLowerCase();
  if (!/^\d+[kmg]?$/.test(s)) throw new Error(`proxy-stream-large-bodies must look like 512k / 1m / 1g, got "${raw}"`);
  return s;
}

/**
 * disable-sudo is tri-state (review H2). Unset means ON in enforce mode: with sudo any step
 * can switch the egress controls off, so enforce is only a boundary without it. A non-empty
 * sudo-config is an explicit sudo policy and keeps sudo unless disable-sudo is set. Explicit
 * true/false always wins. action.yaml declares no default for disable-sudo, so the runner
 * leaves the input empty when the workflow doesn't set it (getBooleanInput would collapse
 * "unset" and "false"). Returns [effective value, whether it was defaulted].
 */
export function resolveDisableSudo(raw: string, mode: Mode, sudoConfig: string): [boolean, boolean] {
  const v = (raw || '').trim();
  if (v === '') return [mode === 'enforce' && sudoConfig.trim() === '', true];
  if (['true', 'True', 'TRUE'].includes(v)) return [true, false];
  if (['false', 'False', 'FALSE'].includes(v)) return [false, false];
  throw new Error(`disable-sudo must be true or false, got "${raw}"`);
}

/**
 * disable-docker is tri-state, mirroring disable-sudo (review H2). Docker group membership is
 * root-equivalent, so a step can use it to remove the egress controls; unset therefore means ON
 * in enforce mode, off in analyze. Explicit true/false always wins. action.yaml declares no
 * default for disable-docker, so the runner leaves the input empty when the workflow doesn't set
 * it (getBooleanInput would collapse "unset" and "false"). Returns [effective value, defaulted].
 */
export function resolveDisableDocker(raw: string, mode: Mode): [boolean, boolean] {
  const v = (raw || '').trim();
  if (v === '') return [mode === 'enforce', true];
  if (['true', 'True', 'TRUE'].includes(v)) return [true, false];
  if (['false', 'False', 'FALSE'].includes(v)) return [false, false];
  throw new Error(`disable-docker must be true or false, got "${raw}"`);
}

function bool(name: string): boolean {
  // getBooleanInput throws on an empty value (e.g. when inputs are absent in the pre step on a local action)
  const v = core.getInput(name);
  return v === '' ? false : core.getBooleanInput(name);
}

export function readInputs(): Inputs {
  const mode = parseMode(core.getInput('mode'));
  const sudoConfig = core.getInput('sudo-config');
  // core.getInput reads the raw INPUT_DISABLE-SUDO variable ('' when unset - no action.yaml default)
  const [disableSudo, disableSudoDefaulted] = resolveDisableSudo(core.getInput('disable-sudo'), mode, sudoConfig);
  // core.getInput reads the raw INPUT_DISABLE-DOCKER variable ('' when unset - no action.yaml default)
  const [disableDocker, disableDockerDefaulted] = resolveDisableDocker(core.getInput('disable-docker'), mode);
  const [containerTls, containerTlsWarning] = parseContainerTls(core.getInput('container-tls'));
  return {
    mode,
    allowedDomains: core.getInput('allowed-domains'),
    passthroughDomains: core.getInput('passthrough-domains'),
    blockRiskySubdomains:
      core.getInput('block-risky-github-subdomains') === '' ? true : bool('block-risky-github-subdomains'),
    primaryDnsServer: core.getInput('primary-dns-server') || '9.9.9.9',
    // action.yaml supplies the Quad9 default; an explicit '' disables the secondary (M1)
    secondaryDnsServer: core.getInput('secondary-dns-server'),
    disableSudo,
    disableSudoDefaulted,
    sudoConfig,
    disableDocker,
    disableDockerDefaulted,
    stopDocker: bool('stop-docker'),
    failOnTampering: bool('fail-on-tampering'),
    proxyPort: parsePort(core.getInput('proxy-port')),
    streamLargeBodies: parseSize(core.getInput('proxy-stream-large-bodies')),
    containerTls,
    containerTlsWarning
  };
}
