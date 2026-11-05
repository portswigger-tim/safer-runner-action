import { PROXY_PORT_BAND, allocateProxyPorts, mitmdumpArgs } from './proxy';

describe('mitmdumpArgs', () => {
  const args = mitmdumpArgs({ port: 8080, containerPort: 8081 });

  it('runs one transparent listener for the host and one for containers', () => {
    expect(args.filter(a => a.startsWith('transparent@'))).toEqual([
      'transparent@127.0.0.1:8080',
      'transparent@127.0.0.1:8081'
    ]);
    // listen-port would apply to every mode without its own port and collide
    expect(args).not.toContain('--listen-port');
  });

  it('keeps the settings repoint depends on', () => {
    expect(args).toContain('connection_strategy=lazy');
  });

  it('streams large bodies at the internal threshold', () => {
    expect(args).toContain('stream_large_bodies=1m');
  });
});

describe('allocateProxyPorts', () => {
  it('picks a free consecutive pair in the band, below the ephemeral range', async () => {
    const taken = new Set([20000, 20001 + 1]);
    const seq = [0, 0.0000001, 0.5];
    const r = await allocateProxyPorts(
      async p => !taken.has(p),
      () => seq.shift() ?? 0.5
    );
    expect(r.containerPort).toBe(r.port + 1);
    expect(r.port).toBeGreaterThanOrEqual(PROXY_PORT_BAND[0]);
    expect(r.containerPort).toBeLessThanOrEqual(PROXY_PORT_BAND[1] + 1);
    expect(r.containerPort).toBeLessThan(32768);
    expect(taken.has(r.port) || taken.has(r.containerPort)).toBe(false);
  });

  it('fails loudly when nothing is free', async () => {
    await expect(allocateProxyPorts(async () => false)).rejects.toThrow(/no free pair/);
  });

  it('really binds on this machine', async () => {
    const r = await allocateProxyPorts();
    expect(r.containerPort).toBe(r.port + 1);
  });
});
