/**
 * v2 action inputs (see action.yaml).
 */

import * as core from '@actions/core';
import type { Mode } from './policy';

export interface Inputs {
  mode: Mode;
  allowedDomains: string;
  passthroughDomains: string;
  blockRiskySubdomains: boolean;
  primaryDnsServer: string;
  /** '' disables the secondary server */
  secondaryDnsServer: string;
  disableSudo: boolean;
  sudoConfig: string;
  disableDocker: boolean;
  stopDocker: boolean;
  failOnTampering: boolean;
  proxyPort: number;
  streamLargeBodies: string;
}

export function parseMode(raw: string): Mode {
  const m = (raw || 'analyze').trim().toLowerCase();
  if (m !== 'analyze' && m !== 'enforce') {
    throw new Error(`mode must be "analyze" or "enforce", got "${raw}"`);
  }
  return m;
}

export function parsePort(raw: string): number {
  const n = Number((raw || '8080').trim());
  if (!Number.isInteger(n) || n < 1024 || n > 65535) {
    throw new Error(`proxy-port must be an integer between 1024 and 65535, got "${raw}"`);
  }
  return n;
}

export function parseSize(raw: string): string {
  const s = (raw || '1m').trim().toLowerCase();
  if (!/^\d+[kmg]?$/.test(s)) throw new Error(`proxy-stream-large-bodies must look like 512k / 1m / 1g, got "${raw}"`);
  return s;
}

function bool(name: string): boolean {
  // getBooleanInput throws on an empty value (e.g. when inputs are absent in the pre step on a local action)
  const v = core.getInput(name);
  return v === '' ? false : core.getBooleanInput(name);
}

export function readInputs(): Inputs {
  return {
    mode: parseMode(core.getInput('mode')),
    allowedDomains: core.getInput('allowed-domains'),
    passthroughDomains: core.getInput('passthrough-domains'),
    blockRiskySubdomains:
      core.getInput('block-risky-github-subdomains') === '' ? true : bool('block-risky-github-subdomains'),
    primaryDnsServer: core.getInput('primary-dns-server') || '9.9.9.9',
    // action.yaml supplies the Quad9 default; an explicit '' disables the secondary (M1)
    secondaryDnsServer: core.getInput('secondary-dns-server'),
    disableSudo: bool('disable-sudo'),
    sudoConfig: core.getInput('sudo-config'),
    disableDocker: bool('disable-docker'),
    stopDocker: bool('stop-docker'),
    failOnTampering: bool('fail-on-tampering'),
    proxyPort: parsePort(core.getInput('proxy-port')),
    streamLargeBodies: parseSize(core.getInput('proxy-stream-large-bodies'))
  };
}
