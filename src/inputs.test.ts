import * as core from '@actions/core';
import {
  DEFAULT_DNS_SERVERS,
  effectiveFailOnTampering,
  parseDnsServers,
  readInputs,
  resolveDisableSudo,
  resolveDocker,
  resolveFailOnTampering
} from './inputs';

jest.mock('@actions/core');

describe('resolveDisableSudo (review H2: enforce removes sudo by default)', () => {
  it('defaults ON in enforce mode when disable-sudo is unset', () => {
    expect(resolveDisableSudo('', 'enforce')).toEqual([true, true]);
    expect(resolveDisableSudo('  ', 'enforce')).toEqual([true, true]);
  });

  it('defaults off in analyze mode', () => {
    expect(resolveDisableSudo('', 'analyze')).toEqual([false, true]);
  });

  it('honours an explicit false in enforce (the advisory opt-out) - unset and false differ', () => {
    expect(resolveDisableSudo('false', 'enforce')).toEqual([false, false]);
    expect(resolveDisableSudo('FALSE', 'enforce')).toEqual([false, false]);
  });

  it('honours an explicit true in any mode', () => {
    expect(resolveDisableSudo('true', 'analyze')).toEqual([true, false]);
    expect(resolveDisableSudo('True', 'enforce')).toEqual([true, false]);
  });

  it('rejects anything that is not a YAML boolean', () => {
    expect(() => resolveDisableSudo('yes', 'enforce')).toThrow(/disable-sudo must be true or false/);
    expect(() => resolveDisableSudo('0', 'enforce')).toThrow();
  });
});

describe('resolveDocker (enforce removes docker by default)', () => {
  it('defaults to remove-group in enforce and keep in analyze', () => {
    expect(resolveDocker('', 'enforce')).toEqual(['remove-group', true]);
    expect(resolveDocker('  ', 'enforce')).toEqual(['remove-group', true]);
    expect(resolveDocker('', 'analyze')).toEqual(['keep', true]);
  });

  it('an explicit value always wins, in either mode', () => {
    expect(resolveDocker('keep', 'enforce')).toEqual(['keep', false]);
    expect(resolveDocker('stop', 'enforce')).toEqual(['stop', false]);
    expect(resolveDocker(' Remove-Group ', 'analyze')).toEqual(['remove-group', false]);
    expect(resolveDocker('stop', 'analyze')).toEqual(['stop', false]);
  });

  it('rejects the old boolean spellings and anything else', () => {
    expect(() => resolveDocker('true', 'enforce')).toThrow(/docker must be one of keep, remove-group, stop/);
    expect(() => resolveDocker('false', 'enforce')).toThrow();
    expect(() => resolveDocker('disable', 'enforce')).toThrow();
  });
});

describe('resolveFailOnTampering (mode-aware)', () => {
  it('defaults ON in enforce and off in analyze', () => {
    expect(resolveFailOnTampering('', 'enforce')).toEqual([true, true]);
    expect(resolveFailOnTampering('', 'analyze')).toEqual([false, true]);
  });

  it('an explicit value always wins', () => {
    expect(resolveFailOnTampering('false', 'enforce')).toEqual([false, false]);
    expect(resolveFailOnTampering('true', 'analyze')).toEqual([true, false]);
  });

  it('rejects anything that is not a YAML boolean', () => {
    expect(() => resolveFailOnTampering('on', 'enforce')).toThrow(/fail-on-tampering must be true or false/);
  });

  it('the post step trusts the value setup recorded, and resolves the input only without one', () => {
    expect(effectiveFailOnTampering(false, 'true', 'enforce')).toBe(false);
    expect(effectiveFailOnTampering(true, '', 'analyze')).toBe(true);
    expect(effectiveFailOnTampering(undefined, '', 'enforce')).toBe(true);
    expect(effectiveFailOnTampering(undefined, '', 'analyze')).toBe(false);
  });
});

describe('parseDnsServers', () => {
  it('defaults to Quad9 when empty (never no resolver)', () => {
    expect(parseDnsServers('')).toEqual(['9.9.9.9', '149.112.112.112']);
    expect(parseDnsServers(' \n ,')).toEqual(DEFAULT_DNS_SERVERS);
  });

  it('accepts space, comma and newline separated lists, primary first', () => {
    expect(parseDnsServers('1.1.1.1')).toEqual(['1.1.1.1']);
    expect(parseDnsServers('1.1.1.1, 1.0.0.1\n8.8.8.8 2606:4700:4700::1111')).toEqual([
      '1.1.1.1',
      '1.0.0.1',
      '8.8.8.8',
      '2606:4700:4700::1111'
    ]);
    expect(parseDnsServers('1.1.1.1 1.1.1.1 9.9.9.9')).toEqual(['1.1.1.1', '9.9.9.9']);
  });

  it('rejects anything that is not an IP address', () => {
    expect(() => parseDnsServers('dns.quad9.net')).toThrow(/dns-servers: 'dns.quad9.net' is not an IP address/);
    expect(() => parseDnsServers('9.9.9.9 }')).toThrow();
  });
});

describe('readInputs', () => {
  const inputs = (values: Record<string, string>) =>
    (core.getInput as jest.Mock).mockImplementation((name: string) => values[name] ?? '');

  it('enforce with nothing set: sudo removed, docker remove-group, fail-on-tampering on, Quad9', () => {
    inputs({ mode: 'enforce' });
    expect(readInputs()).toMatchObject({
      mode: 'enforce',
      disableSudo: true,
      disableSudoDefaulted: true,
      docker: 'remove-group',
      dockerDefaulted: true,
      failOnTampering: true,
      dnsServers: ['9.9.9.9', '149.112.112.112'],
      blockRiskySubdomains: true
    });
  });

  it('analyze with nothing set changes nothing on the runner', () => {
    inputs({});
    expect(readInputs()).toMatchObject({
      mode: 'analyze',
      disableSudo: false,
      docker: 'keep',
      failOnTampering: false
    });
  });

  it('has no removed inputs left in its result', () => {
    inputs({ mode: 'enforce' });
    const keys = Object.keys(readInputs());
    for (const gone of [
      'proxyPort',
      'streamLargeBodies',
      'containerTls',
      'sudoConfig',
      'disableDocker',
      'stopDocker'
    ]) {
      expect(keys).not.toContain(gone);
    }
  });
});
