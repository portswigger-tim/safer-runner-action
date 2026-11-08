import * as core from '@actions/core';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DOWNLOAD_ATTEMPTS, DOWNLOAD_TIMEOUT_MS, backoffMs, downloadVerified } from './install';

jest.mock('@actions/core');

const BODY = Buffer.from('pinned tarball');
const SHA = crypto.createHash('sha256').update(BODY).digest('hex');
const URL = 'https://example.org/coredns.tgz';

type Reply = number | 'hang' | 'reset' | Buffer;

/** fetch that answers each attempt in turn: a status, a body, a dropped connection, or nothing. */
function fetchReplies(replies: Reply[]): jest.Mock {
  let calls = 0;
  const mock: jest.Mock = jest.fn(async (_url: string, init?: RequestInit): Promise<Response> => {
    const r = replies[calls++];
    if (r === 'reset') throw new TypeError('fetch failed');
    if (r === 'hang') {
      return new Promise<Response>((_, reject) =>
        init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
      );
    }
    return typeof r === 'number' ? new Response('', { status: r }) : new Response(r);
  });
  global.fetch = mock as unknown as typeof fetch;
  return mock;
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

  /** Run a download to completion on the fake clock; the ms it took. */
  async function run(): Promise<{ ms: number; error?: unknown }> {
    const t0 = Date.now();
    let done = false;
    let error: unknown;
    downloadVerified(URL, SHA, dest, 'coredns').then(
      () => (done = true),
      e => ((done = true), (error = e))
    );
    for (let i = 0; i < 10_000 && !done; i++) await jest.advanceTimersByTimeAsync(100);
    expect(done).toBe(true);
    return { ms: Date.now() - t0, error };
  }

  it('rides out a transient 5xx with exponential backoff, then verifies and writes the file', async () => {
    const f = fetchReplies([504, 504, 'reset', 502, BODY]);
    const { ms, error } = await run();
    expect(error).toBeUndefined();
    expect(f).toHaveBeenCalledTimes(5);
    expect(fs.readFileSync(dest)).toEqual(BODY);
    // 1 + 2 + 4 + 8 seconds between the five attempts
    expect(ms).toBeGreaterThanOrEqual(15_000);
    expect(ms).toBeLessThan(16_000);
    expect(core.warning).toHaveBeenCalledWith('coredns download attempt 1/5 failed: Error: HTTP 504');
    expect(core.warning).toHaveBeenCalledWith('coredns download attempt 3/5 failed: TypeError: fetch failed');
  });

  it(`gives up after ${DOWNLOAD_ATTEMPTS} attempts`, async () => {
    const f = fetchReplies([504, 504, 504, 504, 504, BODY]);
    const { error } = await run();
    expect(f).toHaveBeenCalledTimes(DOWNLOAD_ATTEMPTS);
    expect(String(error)).toBe('Error: could not download coredns: Error: HTTP 504');
    expect(fs.existsSync(dest)).toBe(false);
  });

  it('times out a request that hangs, and retries', async () => {
    const f = fetchReplies(['hang', BODY]);
    const { ms, error } = await run();
    expect(error).toBeUndefined();
    expect(f).toHaveBeenCalledTimes(2);
    expect(ms).toBeGreaterThanOrEqual(DOWNLOAD_TIMEOUT_MS + 1_000);
    expect(core.warning).toHaveBeenCalledWith(
      `coredns download attempt 1/5 failed: Error: timed out after ${DOWNLOAD_TIMEOUT_MS / 1000}s`
    );
  });

  it('never retries a digest mismatch, and writes nothing', async () => {
    const f = fetchReplies([Buffer.from('something else'), BODY]);
    const { error } = await run();
    expect(f).toHaveBeenCalledTimes(1);
    expect(String(error)).toMatch(/could not download coredns: Error: sha256 mismatch for .*want [0-9a-f]{64}/);
    expect(fs.existsSync(dest)).toBe(false);
  });
});

describe('backoffMs', () => {
  it('doubles from 1s, capped at 10s, with 50-150% jitter', () => {
    expect([1, 2, 3, 4, 5, 6].map(n => backoffMs(n, () => 0.5))).toEqual([1000, 2000, 4000, 8000, 10000, 10000]);
    expect(backoffMs(1, () => 0)).toBe(500);
    expect(backoffMs(4, () => 0.999)).toBe(11992);
  });
});
