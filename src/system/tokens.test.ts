/**
 * Readiness tokens (see src/system/types.ts): each is declared and minted only in the module that
 * owns its step, and each has an ordering invariant in src/orchestration.test.ts. A new token
 * goes in TOKENS with both, or this fails.
 */

import * as fs from 'fs';
import * as path from 'path';

const SRC = path.join(__dirname, '..');

/** token -> the file that declares and mints it, and the orchestration invariants that check its order */
const TOKENS: Record<string, { owner: string; invariants: string[] }> = {
  DnsReady: { owner: 'services/coredns/index.ts', invariants: ['L11'] },
  ResolverOn: { owner: 'services/coredns/index.ts', invariants: ['L11'] },
  ProxyConfigWritten: { owner: 'services/mitmproxy/index.ts', invariants: ['L6', 'L7'] },
  CaReady: { owner: 'services/mitmproxy/ca.ts', invariants: ['L8'] },
  ProxyReady: { owner: 'services/mitmproxy/index.ts', invariants: ['L9'] },
  TrustInstalled: { owner: 'services/mitmproxy/trust.ts', invariants: ['L10'] },
  FirewallOn: { owner: 'services/iptables/index.ts', invariants: ['L14', 'L15'] },
  DockerPrepared: { owner: 'services/docker/index.ts', invariants: ['L12'] },
  SelfTestsRun: { owner: 'setup/selftest.ts', invariants: ['L15', 'L16'] },
  SudoLogging: { owner: 'services/sudo/index.ts', invariants: ['L18'] },
  BaselineCaptured: { owner: 'integrity/baseline.ts', invariants: ['L19', 'L21'] }
};

function sources(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return sources(p);
    return e.name.endsWith('.ts') && !e.name.endsWith('.test.ts') ? [p] : [];
  });
}

const files = sources(SRC).map(p => ({ rel: path.relative(SRC, p), text: fs.readFileSync(p, 'utf8') }));

describe('readiness tokens', () => {
  it('every token declared in src is listed here', () => {
    const declared = files.flatMap(f =>
      [...f.text.matchAll(/export type (\w+) = \{ readonly \[\w+\]: true \}/g)].map(m => `${m[1]} ${f.rel}`)
    );
    expect(declared.sort()).toEqual(
      Object.entries(TOKENS)
        .map(([t, { owner }]) => `${t} ${owner}`)
        .sort()
    );
  });

  it.each(Object.entries(TOKENS))('%s is minted only in its owning module', (token, { owner }) => {
    // `as T`, `as ns.T`, `as import('..').T` and `<T>x`
    const ref = `(?:import\\([^)]*\\)\\.)?(?:\\w+\\.)*${token}\\b`;
    const cast = new RegExp(`\\bas\\s+${ref}|<\\s*${ref}\\s*>`);
    const minted = files.filter(f => cast.test(f.text)).map(f => f.rel);
    expect(minted).toEqual([owner]);
  });

  it.each(Object.entries(TOKENS))(
    '%s has an ordering invariant in the orchestration nets',
    (_token, { invariants }) => {
      const nets = fs.readFileSync(path.join(SRC, 'orchestration.test.ts'), 'utf8');
      for (const id of invariants) expect(nets).toContain(`before('${id}'`);
    }
  );
});

/**
 * Validated inputs: a branded type made only by its parser or planner, so security-relevant
 * text (the sudoers file) is never built from a string that was not checked, and a privilege
 * change (docker access) is never made outside enforce.
 */
const VALIDATED: Record<string, string> = {
  SudoRule: 'services/sudo/config.ts',
  ApplyingDocker: 'services/docker/config.ts'
};

describe('validated inputs', () => {
  it.each(Object.entries(VALIDATED))('%s is made only by its parser', (type, owner) => {
    const ref = `(?:import\\([^)]*\\)\\.)?(?:\\w+\\.)*${type}\\b`;
    const cast = new RegExp(`\\bas\\s+${ref}|<\\s*${ref}\\s*>`);
    expect(files.filter(f => cast.test(f.text)).map(f => f.rel)).toEqual([owner]);
  });
});
