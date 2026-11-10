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

  it('enforce with docker kept: ADVISORY, and the numbers cell says so', () => {
    const s = report({ retained: true, docker: { requested: 'keep', access: 'retained' } }, ENFORCE);
    expect(s.stat).toBe('⚠️ kept');
    expect(s.advisory.map(a => a.label)).toEqual(['docker kept']);
  });

  it('enforce: removed, stopped or not running, as verified at setup', () => {
    const stat = (requested: string, access: 'group-removed' | 'not-running') =>
      report({ retained: false, docker: { requested, access } }, ENFORCE).stat;
    expect(stat('remove-group', 'group-removed')).toBe('removed');
    expect(stat('stop', 'not-running')).toBe('stopped');
    expect(stat('remove-group', 'not-running')).toBe('not running');
  });

  it('analyze: a use enforce would block is a row, and docker: keep is suggested as ADVISORY', () => {
    const s = report(
      { retained: true, docker: { requested: 'remove-group', access: 'retained' }, policy: used },
      ANALYZE
    );
    // the suggested docker: keep makes enforce ADVISORY
    expect(s.stat).toBe('⚠️ 2');
    expect(s.blocked).toEqual([
      { reason: '`docker: remove-group`', layer: 'docker', tries: 2, what: '2 container actions' }
    ]);
    expect(s.suggestions).toEqual([{ input: 'docker', value: 'keep', advisory: 'ADVISORY' }]);
    expect(s.advisory).toEqual([]);
  });

  it("the action's docker change (and the dockerd CA restart) go in Safer Runner's part", () => {
    const s = report(
      { retained: false, docker: { requested: 'remove-group', access: 'group-removed', caRestart: true } },
      ENFORCE
    );
    expect(s.checks).toEqual([
      {
        ok: true,
        check: '`docker: remove-group`',
        detail: 'runner user removed from the docker group, socket root-only'
      },
      { ok: true, check: 'dockerd restart', detail: 'restarted so it trusts the proxy CA' }
    ]);
  });

  it('analyze, dockerd running but not evaluated (the evaluation failed): not recorded, never 0', () => {
    const s = report({ retained: true, docker: { requested: 'remove-group', access: 'retained' } }, ANALYZE);
    expect(s.stat).toBe('not recorded');
    const notRunning = report(
      { retained: false, docker: { requested: 'remove-group', access: 'not-running' } },
      ANALYZE
    );
    expect(notRunning.stat).toBe('not running');
  });

  it('analyze, a recording that did not cover the whole job: partial, in the cell and a note', () => {
    const partial = { ...observed, uses: {}, partial: true };
    const s = report(
      {
        retained: true,
        docker: { requested: 'keep', access: 'retained' },
        policy: { policy: 'keep', observed: partial, evaluation: evaluateDocker('keep', partial) }
      },
      ANALYZE
    );
    expect(s.stat).toBe('⚠️ 0, partial');
    expect(s.notes).toContainEqual(expect.stringContaining('did not cover the whole job'));
  });

  it('job log: the uses enforce would block', () => {
    expect(jobLog(used)).toEqual(['docker WOULD_BLOCK container x2']);
  });
});
