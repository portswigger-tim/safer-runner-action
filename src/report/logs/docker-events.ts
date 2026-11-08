/** Parser for the docker events the analyze recorder writes (`docker events --format '{{json .}}'`). */

/** One docker event, as the post step keeps it. */
export interface DockerEvent {
  /** `container`, `image`, `network`, `volume`, `daemon`, `builder`, ... */
  type: string;
  /** the action, without the command an exec action carries (`exec_create: sh -c x` -> `exec_create`) */
  action: string;
  /** exec actions: the command line, only to tell a container's healthcheck apart. Never shown. */
  command?: string;
  /** the container, image, network or volume */
  id: string;
  /** the image: of a container (container events), or the image itself (image events) */
  image?: string;
}

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

/** Parse the recorder's log; a line that is not a docker event is skipped. */
export function parseDockerEvents(text: string): DockerEvent[] {
  const out: DockerEvent[] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let e: Record<string, unknown>;
    try {
      e = JSON.parse(line);
    } catch {
      continue;
    }
    if (e === null || typeof e !== 'object') continue;
    const actor = (e.Actor ?? {}) as Record<string, unknown>;
    const attrs = (actor.Attributes ?? {}) as Record<string, unknown>;
    const type = str(e.Type);
    const raw = str(e.Action);
    const id = str(actor.ID) ?? '';
    if (!type || !raw) continue;
    const sep = raw.indexOf(': ');
    const action = sep < 0 ? raw : raw.slice(0, sep);
    const command = sep < 0 ? undefined : raw.slice(sep + 2);
    // image events: the reference (`alpine:3.20`), or for an image ID (`sha256:...`) its name
    const image =
      type === 'container'
        ? str(attrs.image)
        : type === 'image'
          ? id.startsWith('sha256:')
            ? str(attrs.name)
            : id
          : undefined;
    out.push({ type, action, id, ...(command !== undefined ? { command } : {}), ...(image ? { image } : {}) });
  }
  return out;
}
