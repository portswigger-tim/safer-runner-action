import * as crypto from 'crypto';
import { looksEncoded, needsRedaction, redactName } from './redact';

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
    'x'.repeat(63)
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
    'ec2-54-12-33-1',
    'prod-eastus2-01',
    'cloudfront',
    'dead',
    'release-assets'
  ];
  it.each(words)('shows %p', l => expect(looksEncoded(l)).toBe(false));
});

describe('redactName', () => {
  it('keeps the registrable domain and hides only payload-looking labels', () => {
    expect(redactName('aghvsbg8gd29ybgq.attacker.com')).toBe('‹16 chars›.attacker.com');
    expect(redactName('aghvsbg8gd29ybgq.www.github.com')).toBe('‹16 chars›.www.github.com');
    expect(redactName('0dd2149bb6f23853.f4crg4pntvrqdozj.evil.co.uk')).toBe('‹16 chars›.‹16 chars›.evil.co.uk');
  });

  it('never hides the zone, even when it looks encoded', () => {
    expect(redactName('0dd2149bb6f23853.com')).toBe('0dd2149bb6f23853.com');
  });

  it('keeps a longer caller-given suffix (the allowlisted parent)', () => {
    expect(redactName('c2vjcmv0lxrva2vulteymzq.objects.githubusercontent.com', 'objects.githubusercontent.com')).toBe(
      '‹23 chars›.objects.githubusercontent.com'
    );
  });

  it('leaves ordinary names alone (lower-cased)', () => {
    expect(redactName('Registry-1.Docker.io')).toBe('registry-1.docker.io');
    expect(redactName('hosted-compute-watchdog-prod-iad-01.githubapp.com')).toBe(
      'hosted-compute-watchdog-prod-iad-01.githubapp.com'
    );
    expect(needsRedaction('pipelines.actions.githubusercontent.com')).toBe(false);
    expect(needsRedaction('0dd2149bb6f23853.example.org')).toBe(true);
  });
});
