import * as core from '@actions/core';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { COREDNS_SHA256, COREDNS_SOURCES, COREDNS_URL } from '../constants';
import { DOWNLOAD_ATTEMPTS, DOWNLOAD_TIMEOUT_MS, backoffMs, downloadVerified, type DownloadSource } from './install';

jest.mock('@actions/core');

const BODY = Buffer.from('pinned tarball');
const SHA = crypto.createHash('sha256').update(BODY).digest('hex');
const API: DownloadSource = { url: 'https://api.github.com/repos/o/r/releases/assets/1', api: true };
const DIRECT: DownloadSource = { url: 'https://github.com/o/r/releases/download/v1/x.tgz' };

type Reply = number | 'hang' | 'reset' | Buffer;

/**
 * fetch that answers each request in turn, per host: a status, a body, a dropped connection, or
 * nothing (until the request is aborted). Records the requests in order.
 */
function fetchReplies(byHost: Record<string, Reply[]>): {
  requests: { host: string; headers: Record<string, string> }[];
} {
  const requests: { host: string; headers: Record<string, string> }[] = [];
  const next: Record<string, number> = {};
  global.fetch = jest.fn(async (url: string, init?: RequestInit): Promise<Response> => {
    const host = new URL(url).host;
    requests.push({ host, headers: { ...(init?.headers as Record<string, string>) } });
    const r = byHost[host]?.[(next[host] = (next[host] ?? 0) + 1) - 1];
    if (r === undefined) throw new Error(`no reply for ${host}`);
    if (r === 'reset') throw new TypeError('fetch failed');
    if (r === 'hang') {
      return new Promise<Response>((_, reject) =>
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
      );
    }
    return typeof r === 'number' ? new Response('', { status: r }) : new Response(r);
  }) as unknown as typeof fetch;
  return { requests };
}

describe('downloadVerified', () => {
  let dir: string;
  let dest: string;
  const savedFetch = global.fetch;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers({ doNotFake: ['nextTick', 'setImmediate', 'queueMicrotask'] });
    jest.spyOn(Math, 'random').mockReturnValue(0.5); // no jitter: 1s, 2s, 4s, 8s
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'safer-runner-dl-'));
    dest = path.join(dir, 'coredns.tgz');
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
    global.fetch = savedFetch;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  /** Run a download to completion on the fake clock; the ms it took and the error, if any. */
  async function run(sources: DownloadSource[]): Promise<{ ms: number; error?: unknown }> {
    const t0 = Date.now();
    let done = false;
    let error: unknown;
    downloadVerified(sources, SHA, dest, 'coredns').then(
      () => (done = true),
      e => ((done = true), (error = e))
    );
    for (let i = 0; i < 10_000 && !done; i++) await jest.advanceTimersByTimeAsync(100);
    expect(done).toBe(true);
    return { ms: Date.now() - t0, error };
  }

  describe('one source', () => {
    it('rides out a transient 5xx with exponential backoff, then verifies and writes the file', async () => {
      const { requests } = fetchReplies({ 'github.com': [504, 504, 'reset', 502, BODY] });
      const { ms, error } = await run([DIRECT]);
      expect(error).toBeUndefined();
      expect(requests).toHaveLength(5);
      expect(fs.readFileSync(dest)).toEqual(BODY);
      // 1 + 2 + 4 + 8 seconds between the five attempts
      expect(ms).toBeGreaterThanOrEqual(15_000);
      expect(ms).toBeLessThan(16_000);
      expect(core.warning).toHaveBeenCalledWith(
        'coredns download from github.com failed (attempt 1/5): Error: HTTP 504'
      );
      expect(core.warning).toHaveBeenCalledWith(
        'coredns download from github.com failed (attempt 3/5): TypeError: fetch failed'
      );
      expect(core.info).toHaveBeenCalledWith('coredns: downloaded from github.com, sha256 verified');
    });

    it(`gives up after ${DOWNLOAD_ATTEMPTS} attempts`, async () => {
      const { requests } = fetchReplies({ 'github.com': [504, 504, 504, 504, 504, BODY] });
      const { error } = await run([DIRECT]);
      expect(requests).toHaveLength(DOWNLOAD_ATTEMPTS);
      expect(String(error)).toBe('Error: could not download coredns: Error: HTTP 504');
      expect(fs.existsSync(dest)).toBe(false);
    });

    it('times out a request that hangs, and retries', async () => {
      const { requests } = fetchReplies({ 'github.com': ['hang', BODY] });
      const { ms, error } = await run([DIRECT]);
      expect(error).toBeUndefined();
      expect(requests).toHaveLength(2);
      expect(ms).toBeGreaterThanOrEqual(DOWNLOAD_TIMEOUT_MS + 1_000);
      expect(core.warning).toHaveBeenCalledWith(
        `coredns download from github.com failed (attempt 1/5): Error: timed out after ${DOWNLOAD_TIMEOUT_MS / 1000}s`
      );
    });

    it('never retries a digest mismatch, and writes nothing', async () => {
      const { requests } = fetchReplies({ 'github.com': [Buffer.from('something else'), BODY] });
      const { error } = await run([DIRECT]);
      expect(requests).toHaveLength(1);
      expect(String(error)).toMatch(/could not download coredns: Error: sha256 mismatch for .*want [0-9a-f]{64}/);
      expect(fs.existsSync(dest)).toBe(false);
    });
  });

  describe('two sources', () => {
    it('a failing source moves straight to the next, with no wait', async () => {
      const { requests } = fetchReplies({ 'api.github.com': [504], 'github.com': [BODY] });
      const { ms, error } = await run([API, DIRECT]);
      expect(error).toBeUndefined();
      expect(requests.map(r => r.host)).toEqual(['api.github.com', 'github.com']);
      expect(ms).toBeLessThan(1_000);
      expect(core.info).toHaveBeenCalledWith('coredns: downloaded from github.com, sha256 verified');
    });

    it('the first source that answers is used; the API source asks for the asset bytes, no credentials', async () => {
      const { requests } = fetchReplies({ 'api.github.com': [BODY] });
      await run([API, DIRECT]);
      expect(requests).toEqual([
        { host: 'api.github.com', headers: { 'user-agent': 'safer-runner-action', accept: 'application/octet-stream' } }
      ]);
      expect(core.info).toHaveBeenCalledWith('coredns: downloaded from api.github.com, sha256 verified');
    });

    it('backs off only between rounds, after every source failed', async () => {
      const { requests } = fetchReplies({ 'api.github.com': [403, 429], 'github.com': [504, BODY] });
      const { ms, error } = await run([API, DIRECT]);
      expect(error).toBeUndefined();
      expect(requests.map(r => r.host)).toEqual(['api.github.com', 'github.com', 'api.github.com', 'github.com']);
      expect(ms).toBeGreaterThanOrEqual(1_000);
      expect(ms).toBeLessThan(2_000);
    });

    it('a source with the wrong digest is skipped from then on; the next is used; it is never written', async () => {
      const { requests } = fetchReplies({ 'api.github.com': [Buffer.from('tampered')], 'github.com': [504, BODY] });
      const { error } = await run([API, DIRECT]);
      expect(error).toBeUndefined();
      expect(requests.map(r => r.host)).toEqual(['api.github.com', 'github.com', 'github.com']);
      expect(fs.readFileSync(dest)).toEqual(BODY);
    });

    it('every source with the wrong digest: fails at once', async () => {
      const { requests } = fetchReplies({ 'api.github.com': [Buffer.from('a')], 'github.com': [Buffer.from('b')] });
      const { ms, error } = await run([API, DIRECT]);
      expect(requests).toHaveLength(2);
      expect(ms).toBeLessThan(1_000);
      expect(String(error)).toMatch(/sha256 mismatch for https:\/\/github\.com/);
      expect(fs.existsSync(dest)).toBe(false);
    });

    it(`every source down: ${DOWNLOAD_ATTEMPTS} rounds, then fails closed`, async () => {
      const down = Array(DOWNLOAD_ATTEMPTS).fill(504);
      const { requests } = fetchReplies({ 'api.github.com': down, 'github.com': down });
      const { error } = await run([API, DIRECT]);
      expect(requests).toHaveLength(2 * DOWNLOAD_ATTEMPTS);
      expect(String(error)).toBe('Error: could not download coredns: Error: HTTP 504');
    });
  });
});

describe('CoreDNS sources', () => {
  it('the API release asset first, then the release download URL; one pinned digest', () => {
    expect(COREDNS_SOURCES).toEqual([
      {
        url: expect.stringMatching(/^https:\/\/api\.github\.com\/repos\/coredns\/coredns\/releases\/assets\/\d+$/),
        api: true
      },
      { url: COREDNS_URL }
    ]);
    expect(COREDNS_SHA256).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('backoffMs', () => {
  it('doubles from 1s, capped at 10s, with 50-150% jitter', () => {
    expect([1, 2, 3, 4, 5, 6].map(n => backoffMs(n, () => 0.5))).toEqual([1000, 2000, 4000, 8000, 10000, 10000]);
    expect(backoffMs(1, () => 0)).toBe(500);
    expect(backoffMs(4, () => 0.999)).toBe(11992);
  });
});
