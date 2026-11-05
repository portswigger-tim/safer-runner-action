/**
 * v2 CA trust injection (docs/DESIGN-v2.md section 5). Trust is not one store: the system
 * bundle covers OpenSSL/GnuTLS consumers (curl, git, python ssl, .NET), Node and several
 * language ecosystems need environment variables, and Java has its own keystores.
 */

import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as fs from 'fs';
import * as path from 'path';
import { CA_BUNDLE, CA_CERT_FILE, SYSTEM_CA_FILE } from './constants';

const JAVA_ALIAS = 'safer-runner-ca';

/**
 * Environment exported to every later step via GITHUB_ENV. Set unconditionally whenever the
 * proxy is active: they are a compatibility mechanism, not a security control.
 */
export function trustEnv(): Record<string, string> {
  return {
    NODE_EXTRA_CA_CERTS: CA_CERT_FILE,
    NODE_USE_SYSTEM_CA: '1',
    REQUESTS_CA_BUNDLE: CA_BUNDLE,
    PIP_CERT: CA_BUNDLE,
    SSL_CERT_FILE: CA_BUNDLE,
    GIT_SSL_CAINFO: CA_BUNDLE,
    AWS_CA_BUNDLE: CA_BUNDLE,
    CURL_CA_BUNDLE: CA_BUNDLE
  };
}

export async function installSystemTrust(): Promise<void> {
  await exec.exec('sudo', ['install', '-m', '0644', '-o', 'root', '-g', 'root', CA_CERT_FILE, SYSTEM_CA_FILE]);
  await exec.exec('sudo', ['update-ca-certificates'], { silent: true });
  const bundle = fs.readFileSync(CA_BUNDLE, 'utf8');
  const ca = fs.readFileSync(CA_CERT_FILE, 'utf8').trim();
  if (!bundle.includes(ca.split('\n').slice(1, 3).join('\n'))) {
    throw new Error(`update-ca-certificates did not add the CA to ${CA_BUNDLE}`);
  }
}

export function exportTrustEnv(): void {
  for (const [k, v] of Object.entries(trustEnv())) {
    core.exportVariable(k, v);
  }
}

/** JDK homes on the runner: JAVA_HOME plus every JAVA_HOME_<n>_<arch> the image sets. */
export function javaHomes(env: NodeJS.ProcessEnv = process.env): string[] {
  const homes = Object.entries(env)
    .filter(([k, v]) => v && (k === 'JAVA_HOME' || /^JAVA_HOME_\d+_[A-Z0-9]+$/.test(k)))
    .map(([, v]) => v as string);
  return Array.from(new Set(homes));
}

/** The cacerts keystore of a JDK home (JDK 9+ layout, then JDK 8's jre/ layout). */
export function cacertsPath(home: string): string | null {
  for (const rel of ['lib/security/cacerts', 'jre/lib/security/cacerts']) {
    const p = path.join(home, rel);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

/**
 * Import the CA into the cacerts of every JDK present now. JDKs installed later (e.g. by
 * actions/setup-java) are not covered - a documented gap.
 */
export async function installJavaTrust(): Promise<string[]> {
  const done = new Set<string>();
  for (const home of javaHomes()) {
    const store = cacertsPath(home);
    const keytool = path.join(home, 'bin', 'keytool');
    if (!store || !fs.existsSync(keytool)) continue;
    const real = fs.realpathSync(store);
    if (done.has(real)) continue;
    done.add(real);
    // -delete first so a re-run doesn't fail on an existing alias
    await exec.exec(
      'sudo',
      [keytool, '-delete', '-noprompt', '-keystore', real, '-storepass', 'changeit', '-alias', JAVA_ALIAS],
      {
        ignoreReturnCode: true,
        silent: true
      }
    );
    const rc = await exec.exec(
      'sudo',
      [
        keytool,
        '-importcert',
        '-noprompt',
        '-keystore',
        real,
        '-storepass',
        'changeit',
        '-alias',
        JAVA_ALIAS,
        '-file',
        CA_CERT_FILE
      ],
      { ignoreReturnCode: true, silent: true }
    );
    if (rc === 0) {
      core.info(`Java: CA imported into ${real}`);
    } else {
      core.warning(`Java: could not import the CA into ${real} (exit ${rc})`);
      done.delete(real);
    }
  }
  return Array.from(done);
}
