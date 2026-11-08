import { REDACTED } from '../redact';
import { dockerUseCount, dockerUseText, imageLabel } from './docker';

describe('imageLabel (an image name in the summary)', () => {
  it('shows ordinary names whole', () => {
    for (const ref of [
      'alpine',
      'alpine:3.20',
      'postgres:16',
      'ghcr.io/acme/app:1.4.2',
      'mcr.microsoft.com/dotnet/sdk:8.0'
    ]) {
      expect(imageLabel(ref)).toBe(ref);
    }
  });

  it('redacts each part that looks encoded: a digest, a tag, a path segment', () => {
    expect(imageLabel(`alpine@sha256:${'ab12'.repeat(16)}`)).toBe(`alpine@sha256:${REDACTED}`);
    expect(imageLabel('ghcr.io/acme/app:5ec7e7c0ffee1234')).toBe(`ghcr.io/acme/app:${REDACTED}`);
    expect(imageLabel('registry.example.com/5ec7e7c0ffee1234/app')).toBe(`registry.example.com/${REDACTED}/app`);
  });

  it('anything an image name cannot hold is not shown at all (no Markdown, no spaces)', () => {
    for (const ref of ['a`b', 'x](http://evil)', 'a b', '<img>', 'a|b', 'a'.repeat(201), '']) {
      expect(imageLabel(ref)).toBe(REDACTED);
    }
  });
});

describe('dockerUseText', () => {
  it('lists each kind with its count, in a fixed order', () => {
    expect(dockerUseText({ image: 2, container: 1, exec: 3 })).toBe(
      '1 container action, 3 execs into containers, 2 image actions'
    );
    expect(dockerUseText({})).toBe('');
    expect(dockerUseCount({ image: 2, container: 1 })).toBe(3);
  });
});
