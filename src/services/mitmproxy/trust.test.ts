import * as core from '@actions/core';
import * as fs from 'fs';
import { CA_BUNDLE, CA_CERT_FILE, SYSTEM_CA_FILE } from '../../constants';
import { recordingHost } from '../../system/testing';
import type { ProxyReady } from '.';
import { cacertsPath, distributeTrust, javaHomes, trustEnv } from './trust';

jest.mock('@actions/core');
jest.mock('fs', () => {
  const actual = jest.requireActual('fs');
  return { ...actual, existsSync: jest.fn(), readFileSync: jest.fn(), realpathSync: jest.fn() };
});
const mockExists = fs.existsSync as unknown as jest.Mock;
const mockRead = fs.readFileSync as unknown as jest.Mock;
const mockRealpath = fs.realpathSync as unknown as jest.Mock;

const CERT = '-----BEGIN CERTIFICATE-----\nAAA1\nAAA2\nAAA3\n-----END CERTIFICATE-----\n';
const PROXY = Object.freeze({}) as ProxyReady;
const JDK17 = '/usr/lib/jvm/temurin-17';
const JDK21 = '/usr/lib/jvm/temurin-21';

/** A runner with two JDKs (JAVA_HOME is the 17 one again) and the CA in the system bundle. */
function runner(opts: { inBundle?: boolean; files?: string[] } = {}): void {
  const files = new Set(
    opts.files ?? [
      `${JDK17}/lib/security/cacerts`,
      `${JDK17}/bin/keytool`,
      `${JDK21}/lib/security/cacerts`,
      `${JDK21}/bin/keytool`
    ]
  );
  mockExists.mockImplementation((p: string) => files.has(p));
  mockRealpath.mockImplementation((p: string) => p);
  mockRead.mockImplementation((p: string) => {
    if (p === CA_CERT_FILE) return CERT;
    if (p === CA_BUNDLE) return `ROOTS\n${opts.inBundle === false ? '' : CERT}`;
    throw new Error(`unexpected read ${p}`);
  });
}

describe('distributeTrust', () => {
  const env = { ...process.env };
  beforeEach(() => {
    jest.clearAllMocks();
    for (const k of Object.keys(process.env)) if (k.startsWith('JAVA_HOME')) delete process.env[k];
    Object.assign(process.env, { JAVA_HOME: JDK17, JAVA_HOME_17_X64: JDK17, JAVA_HOME_21_X64: JDK21 });
  });
  afterAll(() => {
    process.env = env;
  });

  it('system store (checked), exported variables, then every JDK once', async () => {
    runner();
    const { host, calls } = recordingHost();
    await distributeTrust(host, PROXY);
    expect(calls).toEqual([
      `sudo install -m 0644 -o root -g root ${CA_CERT_FILE} ${SYSTEM_CA_FILE}`,
      'sudo update-ca-certificates [silent]',
      `sudo ${JDK17}/bin/keytool -delete -noprompt -keystore ${JDK17}/lib/security/cacerts -storepass changeit -alias safer-runner-ca [ignore-rc] [silent]`,
      `sudo ${JDK17}/bin/keytool -importcert -noprompt -keystore ${JDK17}/lib/security/cacerts -storepass changeit -alias safer-runner-ca -file ${CA_CERT_FILE} [ignore-rc] [silent]`,
      `sudo ${JDK21}/bin/keytool -delete -noprompt -keystore ${JDK21}/lib/security/cacerts -storepass changeit -alias safer-runner-ca [ignore-rc] [silent]`,
      `sudo ${JDK21}/bin/keytool -importcert -noprompt -keystore ${JDK21}/lib/security/cacerts -storepass changeit -alias safer-runner-ca -file ${CA_CERT_FILE} [ignore-rc] [silent]`
    ]);
    expect((core.exportVariable as jest.Mock).mock.calls).toEqual(Object.entries(trustEnv()));
  });

  it('fails when update-ca-certificates did not add the CA (nothing exported, no JDK touched)', async () => {
    runner({ inBundle: false });
    const { host, calls } = recordingHost();
    await expect(distributeTrust(host, PROXY)).rejects.toThrow(
      `update-ca-certificates did not add the CA to ${CA_BUNDLE}`
    );
    expect(core.exportVariable).not.toHaveBeenCalled();
    expect(calls.some(c => c.includes('keytool'))).toBe(false);
  });

  it('a JDK whose import fails is warned about, and the rest still get the CA', async () => {
    runner();
    const { host } = recordingHost(l => (l.includes('-importcert') && l.includes(JDK17) ? 1 : 0));
    await distributeTrust(host, PROXY);
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining(`could not import the CA into ${JDK17}`));
    expect(core.info).toHaveBeenCalledWith(`Java: CA imported into ${JDK21}/lib/security/cacerts`);
  });

  it('needs the proxy up first (a compile-time order check)', () => {
    const { host } = recordingHost();
    // @ts-expect-error - distributing trust before the proxy is proven up does not compile
    const early = () => distributeTrust(host, {});
    expect(early).toBeInstanceOf(Function);
  });
});

describe('trust helpers', () => {
  it('exports the CA to Node, Python, pip, OpenSSL, git, AWS and curl', () => {
    expect(Object.keys(trustEnv())).toEqual([
      'NODE_EXTRA_CA_CERTS',
      'NODE_USE_SYSTEM_CA',
      'REQUESTS_CA_BUNDLE',
      'PIP_CERT',
      'SSL_CERT_FILE',
      'GIT_SSL_CAINFO',
      'AWS_CA_BUNDLE',
      'CURL_CA_BUNDLE'
    ]);
  });

  it('finds JAVA_HOME and every JAVA_HOME_<n>_<arch>, once each', () => {
    expect(
      javaHomes({ JAVA_HOME: '/a', JAVA_HOME_17_X64: '/a', JAVA_HOME_21_ARM64: '/b', JAVA_HOMEX: '/c', PATH: '/d' })
    ).toEqual(['/a', '/b']);
  });

  it('finds cacerts in the JDK 9+ layout, then the JDK 8 jre/ layout', () => {
    runner({ files: ['/jdk8/jre/lib/security/cacerts', '/jdk17/lib/security/cacerts'] });
    expect(cacertsPath('/jdk17')).toBe('/jdk17/lib/security/cacerts');
    expect(cacertsPath('/jdk8')).toBe('/jdk8/jre/lib/security/cacerts');
    expect(cacertsPath('/none')).toBeNull();
  });
});
