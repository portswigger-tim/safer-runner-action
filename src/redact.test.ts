import * as crypto from 'crypto';
import {
  CUSTOM_METHOD,
  PATH_HIDDEN,
  REDACTED,
  looksEncoded,
  methodLabel,
  needsRedaction,
  pathSegmentShown,
  redactName,
  segmentLooksEncoded
} from './redact';

const b32 = (b: Buffer) => {
  const A = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = '';
  for (const x of b) bits += x.toString(2).padStart(8, '0');
  return (bits.match(/.{1,5}/g) ?? []).map(c => A[parseInt(c.padEnd(5, '0'), 2)]).join('');
};

describe('looksEncoded', () => {
  // fixed vectors (lower-cased as DNS delivers them) + fresh random ones each run
  const encoded = [
    'aghvsbg8gd29ybgq', // base64("hello world")
    'c2vjcmv0lxrva2vulteymzq', // base64("secret-token-1234")
    '0dd2149bb6f23853', // 8 bytes hex
    'f4crg4pntvrqdozj', // base32
    's8b3a61a77489531d88e8',
    'ghp1234567890abcdefabcdefabcdef12345678',
    'aGVsbG8tc2VjcmV0LXRva2Vu'.toLowerCase(),
    crypto.randomBytes(16).toString('hex'),
    crypto.randomBytes(32).toString('base64url').toLowerCase(), // 32-byte value, base64url
    crypto.randomBytes(32).toString('base64').replace(/[+/=]/g, '').toLowerCase(), // 32-byte, base64
    b32(crypto.createHash('sha256').update('safer-runner').digest().subarray(0, 20)), // fixed 20-byte base32
    'x'.repeat(63),
    // short labels: digits, or hex with a digit, from 6 chars; base32/64 from 8
    'a1b2c3',
    '482913',
    '9' + crypto.randomBytes(3).toString('hex').slice(1), // 6 hex chars, at least one digit
    'k7xq2zbm' // 5-byte base32
  ];
  it.each(encoded)('redacts %p', l => expect(looksEncoded(l)).toBe(true));

  const words = [
    'www',
    'api',
    'pipelines1',
    'registry-1',
    'hosted-compute-watchdog-prod-iad-01',
    'productionresultssa31',
    'pipelinesghubeus10',
    'runnerghubwus31',
    'results-receiver',
    'run-actions-3-azure-eastus',
    'github-registry-files',
    'microsoftonline',
    's3-us-west-2',
    'prod-eastus2-01',
    'cloudfront',
    'dead',
    'release-assets',
    'jsdelivr',
    'ec2',
    'com'
  ];
  it.each(words)('shows %p', l => expect(looksEncoded(l)).toBe(false));
});

describe('redactName', () => {
  it('hides payload-looking labels, without their length', () => {
    expect(redactName('aghvsbg8gd29ybgq.attacker.com')).toBe(`${REDACTED}.attacker.com`);
    expect(redactName('aghvsbg8gd29ybgq.www.github.com')).toBe(`${REDACTED}.www.github.com`);
    // a run of hidden labels is one marker: the shape of the hidden part says nothing
    expect(redactName('0dd2149bb6f23853.f4crg4pntvrqdozj.evil.co.uk')).toBe(`${REDACTED}.evil.co.uk`);
    expect(redactName('0dd2149bb6f23853.f4crg4pntvrqdozj.evil.co.uk')).toBe(redactName('ab12cd.evil.co.uk'));
  });

  it('checks the registrable domain and the TLD too', () => {
    expect(redactName('0dd2149bb6f23853.com')).toBe(`${REDACTED}.com`);
    expect(redactName('www.c2vjcmv0lxrva2vu')).toBe(`www.${REDACTED}`);
    expect(redactName('cdn.a1b2c3.d4e5f6')).toBe(`cdn.${REDACTED}`);
  });

  it('hides short hex and digit chunks', () => {
    expect(redactName('a1b2c3.d4e5f6.attacker.example')).toBe(`${REDACTED}.attacker.example`);
    expect(redactName('k7xq2zbm.attacker.example')).toBe(`${REDACTED}.attacker.example`);
  });

  it('leaves ordinary names alone (lower-cased)', () => {
    expect(redactName('Registry-1.Docker.io')).toBe('registry-1.docker.io');
    expect(redactName('hosted-compute-watchdog-prod-iad-01.githubapp.com')).toBe(
      'hosted-compute-watchdog-prod-iad-01.githubapp.com'
    );
    for (const n of [
      'pipelines.actions.githubusercontent.com',
      'cdn.jsdelivr.net',
      'dl-cdn.alpinelinux.org',
      'prod-registry-k8s-io-eu-west-1.s3.dualstack.eu-west-1.amazonaws.com',
      'productionresultssa12.blob.core.windows.net',
      'x1.c.lencr.org'
    ]) {
      expect(needsRedaction(n)).toBe(false);
    }
    expect(needsRedaction('0dd2149bb6f23853.example.org')).toBe(true);
  });
});

describe('pathSegmentShown (allowed requests, in a suggested rule)', () => {
  it('rejects encoded-looking parts, like the labels of a name', () => {
    expect(segmentLooksEncoded('notes.0dd2149bb6f23853.txt')).toBe(true);
    for (const seg of ['c2VjcmV0LXRva2VuLTEyMzQ1Njc4', 'notes.0dd2149bb6f23853.txt', '0dd2149bb6f23853']) {
      expect(pathSegmentShown(seg)).toBe(false);
    }
  });

  it('rejects short chunks a hostname label would keep: hex, digit runs, unusual characters', () => {
    for (const seg of ['a1f3', 'cafe', 'dead-beef', 'v123', 'x9y8z7', 'a%20b', 'a;b', 'x'.repeat(65), '..', '']) {
      expect(pathSegmentShown(seg)).toBe(false);
    }
  });

  it('shows ordinary segments', () => {
    for (const seg of [
      'myorg',
      'safer-runner-action.git',
      'git-upload-pack',
      'issues',
      '12',
      'results.services.receiver.v1.ResultsService',
      'requests'
    ]) {
      expect(pathSegmentShown(seg)).toBe(true);
    }
  });
});

describe('methodLabel', () => {
  it('shows standard methods and a fixed word for any other token', () => {
    expect(['get', 'POST', 'Patch', 'OPTIONS', 'TRACE', 'CONNECT'].map(methodLabel)).toEqual([
      'GET',
      'POST',
      'PATCH',
      'OPTIONS',
      'TRACE',
      'CONNECT'
    ]);
    for (const m of ['A1B2C3D4E5F6', 'PROPFIND', '', undefined, 'GET ']) expect(methodLabel(m)).toBe(CUSTOM_METHOD);
    expect(CUSTOM_METHOD).toBe('INVALID');
    expect(PATH_HIDDEN).toBe('‹path hidden›');
  });
});
