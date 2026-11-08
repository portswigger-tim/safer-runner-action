import { REDACTED } from '../../report/redact';
import { evaluateDocker } from './config';
import { dockerUseCount, dockerUseText, imageLabel, jobLog, report } from './report';

describe('imageLabel (an image name in the summary)', () => {
  it('shows ordinary names whole', () => {
    for (const ref of [
      'alpine',
      'alpine:3.20',
      'postgres:16',
      'ghcr.io/acme/app:1.4.2',
      'mcr.microsoft.com/dotnet/sdk:8.0',
      'node:20.11.1-bookworm-slim',
      'public.ecr.aws/docker/library/python:3.12-alpine'
    ]) {
      expect(imageLabel(ref)).toBe(ref);
    }
  });

  it('redacts each part that looks encoded: a digest, a tag, a path segment', () => {
    expect(imageLabel(`alpine@sha256:${'ab12'.repeat(16)}`)).toBe(`alpine@sha256:${REDACTED}`);
    expect(imageLabel('ghcr.io/acme/app:5ec7e7c0ffee1234')).toBe(`ghcr.io/acme/app:${REDACTED}`);
    expect(imageLabel('registry.example.com/5ec7e7c0ffee1234/app')).toBe(`registry.example.com/${REDACTED}/app`);
    // a dotted tag or registry label: each piece is checked on its own
    expect(imageLabel('ghcr.io/acme/app:release.k3j9x8q2')).toBe(`ghcr.io/acme/app:release.${REDACTED}`);
    expect(imageLabel('registry/x:build.a1b2c3')).toBe(`registry/x:build.${REDACTED}`);
    expect(imageLabel('5ec7e7c0ffee1234.example.com/app:1')).toBe(`${REDACTED}.example.com/app:1`);
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

describe('docker report (its Section)', () => {
  const ENFORCE = { mode: 'enforce', enforce: true } as const;
  const ANALYZE = { mode: 'analyze', enforce: false } as const;
  const observed = { uses: { container: 2 }, images: [], services: 0, partial: false };
  const used = { policy: 'remove-group', observed, evaluation: evaluateDocker('remove-group', observed) };

  it('enforce with docker kept: ADVISORY row and chip', () => {
    const s = report({ retained: true, docker: { requested: 'keep', access: 'retained' } }, ENFORCE);
    expect(s.score[0]).toMatchObject({ verdict: 'advisory', area: 'Docker' });
    expect(s.advisory.map(a => a.chip)).toEqual(['⚠️ docker retained']);
  });

  it('analyze: a use enforce would block is a row, and docker: keep is suggested as ADVISORY', () => {
    const s = report(
      { retained: true, docker: { requested: 'remove-group', access: 'retained' }, policy: used },
      ANALYZE
    );
    expect(s.score[0].verdict).toBe('would-block');
    expect(s.suggestions).toEqual([
      { input: 'docker', value: 'keep', advisory: 'docker is root-equivalent: enforce is ADVISORY' }
    ]);
    expect(s.advisory).toEqual([]);
  });

  it("the action's docker change (and the dockerd CA restart) go under Runner System", () => {
    const s = report(
      { retained: false, docker: { requested: 'remove-group', access: 'group-removed', caRestart: true } },
      ENFORCE
    );
    expect(s.runnerSystem[0].summary).toBe('docker removed from the runner user · dockerd restarted to trust the CA');
  });

  it('job log: the uses enforce would block', () => {
    expect(jobLog(used)).toEqual(['docker WOULD_BLOCK container x2']);
  });
});
