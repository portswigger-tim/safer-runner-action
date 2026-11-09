# Limit methods and paths on a host (`http-filter`)

`allowed-domains` controls which hosts a job can connect to, but not what the job does there.
Many hosts that a job must allow also accept writes:

- `github.com`: a step can `git push` stolen data to a repository it controls.
- `registry.npmjs.org`: `npm publish` (an HTTP `PUT`) sends a package out.
- `upload.pypi.org`: `twine upload` (`POST`) sends a package out.
- `ghcr.io` and `registry-1.docker.io`: `docker push` sends image layers out.
- `api.github.com` and other REST APIs: a `POST` or `PUT` sends data out.

GitHub's own hosts are always allowed, so `github.com` and `api.github.com` are always among
them.

`http-filter` adds a second check after the host check. On each host that you name, it allows
only the methods and paths that you list. The proxy decrypts the request, and can therefore see
the method and the path.

`http-filter` can only take access away. It cannot allow a host that is not in
`allowed-domains`. If you name such a host, the filter has no effect, and setup writes a warning.

## Common tasks

### Make a host read-only

Package registries, container registries and REST APIs read with `GET` and `HEAD`, and write with
`PUT`, `POST` and `PATCH`. One line for each host blocks writes, and installs continue to work:

```yaml
- uses: portswigger-tim/safer-runner-action@<sha> # vX.Y.Z
  with:
    mode: enforce
    allowed-domains: |
      registry.npmjs.org pypi.org files.pythonhosted.org
    http-filter: |
      registry.npmjs.org:     { "*": GET, HEAD }   # npm install: yes. npm publish: no.
      pypi.org:               { "*": GET, HEAD }   # pip metadata
      files.pythonhosted.org: { "*": GET, HEAD }   # wheel and sdist downloads
      ghcr.io:                { "*": GET, HEAD }   # docker pull: yes. docker push: no.
      api.github.com:         { "*": GET, HEAD }   # no REST API writes
```

`ghcr.io` and `api.github.com` are GitHub hosts, so you do not add them to `allowed-domains`.

Some reads use `POST`:

- GitHub's GraphQL API uses `POST /graphql` for both reads and writes, so a method rule cannot make
  it read-only. Many `gh` commands and `actions/github-script` calls use GraphQL. Add
  `"graphql": POST` only if you accept GraphQL writes.
- `npm install` and `npm ci` send a `POST` to `/-/npm/v1/security/advisories/bulk` for the audit.
  Use `--no-audit` to skip the audit, or allow that path with `POST`.

### Allow `git push` only to your own repositories

git over HTTPS uses `POST` for both fetch and push, and the method cannot tell them apart. The
path can:

| Operation | Requests |
|---|---|
| clone or fetch | `GET /{owner}/{repo}.git/info/refs?service=git-upload-pack`, then `POST …/git-upload-pack` |
| push | `GET …/info/refs?service=git-receive-pack`, then `POST /{owner}/{repo}.git/git-receive-pack` |

Block the `git-receive-pack` path, and then allow it again for your own organization. The most
specific rule wins:

```yaml
http-filter: |
  github.com:
    "*": "*"                                     # allow everything,
    "*/git-receive-pack": NONE                   # but block all pushes,
    "portswigger-tim/*/git-receive-pack": "*"    # except to this organization
```

To block all pushes, remove the last line. Pushes over SSH are already blocked in `enforce` mode,
because only ports 80 and 443 go through the proxy.

### Build a filter from the job's own traffic

In `analyze` mode, the job summary suggests an `http-filter` from the requests that the job made.
For each host:

1. **Reads become one line**, `"*": GET, HEAD`. Most jobs only read from registries and APIs.
   For most hosts, this line is the complete suggestion.
2. **Write paths become patterns.** Path segments that change from request to request (numbers,
   hashes, IDs) become `*`. The suggestion stays short and does not repeat identifiers.
3. **git stays specific.** A `"*": GET, POST` rule on `github.com` would allow every push. The
   suggestion therefore names each repository that the job fetched from (`git-upload-pack`) or
   pushed to (`git-receive-pack`).

A suggestion for a job that installs from npm, comments on an issue through the GitHub API, and
fetches from and pushes to one repository:

```yaml
http-filter: |
  registry.npmjs.org:
    "*": GET, HEAD
  api.github.com:
    "*": GET, HEAD
    "repos/*/*/issues/*/comments": POST
  github.com:
    "*": GET, HEAD
    "myorg/app/git-receive-pack": POST
    "myorg/app/git-upload-pack": POST
```

This suggestion blocks a clone or fetch of any other repository, for example a submodule or a
second checkout. Add a `git-upload-pack` rule for each repository that the job also needs.

The action never applies a suggestion for you. Review each write rule before you use it: a write
is how data leaves the job. The job summary warns you about a write rule that allows a write on
any path.

In `analyze` mode, the job summary also lists the requests that your current `http-filter` would
block. In `enforce` mode, it lists the requests that it blocked.
[Troubleshooting](TROUBLESHOOTING.md#a-request-is-blocked-by-http-filter) shows what to do when
the job needs one of them.

## Reference

### Rules

`http-filter` is a YAML map (JSON also works). Each key is a host, and each value is a map of
path pattern to methods.

1. **Naming a host blocks everything on it that you do not list.** A request is allowed only if a
   rule matches its path *and* lists its method.
2. **The most specific path wins.** `portswigger-tim/*/git-receive-pack` overrides
   `*/git-receive-pack`, which overrides `*`.
3. **Methods** are a comma-separated list (`GET, POST`), `*` or `ALL` for any method, or `NONE`
   (or an empty list) to block the path. Use `NONE` to remove one path from a `"*": "*"` rule.
4. **`*` works as it does in `allowed-domains`,** with `/` in the place of `.`. A `*` on its own
   as a segment matches one or more segments: `*/git-receive-pack` matches
   `owner/repo/git-receive-pack`, but not `/git-receive-pack`. A `*` inside a segment matches only within that segment
   (`pre*`). There is no `**`.
5. **Case:** methods are not case-sensitive. Paths are case-sensitive, except on `github.com`,
   where the whole path is matched without case, and `.git` is optional on any segment.
   `org/app/git-receive-pack` also matches `/Org/app.git/git-receive-pack`.
6. **The path is matched as the server sees it.** The proxy ignores the query string, and decodes
   percent-encoding once. A request is allowed only if *every* equivalent form of its path is
   allowed: with `;params` removed, repeated slashes merged and trailing slashes removed. The
   proxy blocks a path that contains a malformed or double-encoded escape, a `.` or `..` segment, a
   backslash, a fragment or a control character.

#### Parsing

- A malformed `http-filter` fails the step. In `enforce` mode, the job fails, and does not run
  without the filter.
- These are errors: a duplicate host or path, a YAML anchor, alias, tag or document marker,
  deeper nesting, and methods that are not a string or a list of strings.
- Put a key or value that starts with `*` in quotes.
- In an inline `{ }` rule, a word after a comma with no `:` is another method:
  `{ "*": GET, HEAD }`. A rule with no value means `NONE`.
- Setup writes a warning for a filtered host that is not in `allowed-domains`, or that is in
  `passthrough-domains`, which cannot be filtered.

### GitHub platform endpoints (`allow-github-platform`)

A filter on a GitHub host could stop the Actions platform itself: step logs, job completion,
OIDC, artifacts and the cache. When you filter a host that the platform uses, the action
therefore also allows the platform's endpoints on that host. Each entry names an exact host, path and method.
The action never adds a general read rule.

| Host | Method | Path | Purpose | Tier |
|---|---|---|---|---|
| `results-receiver.actions.githubusercontent.com` | POST | `/twirp/results.services.receiver.Receiver/*` | step and job log metadata | essential |
| `results-receiver.actions.githubusercontent.com` | GET | `/_ws/ingest.sock` | live step-log stream | essential |
| `run-actions-*-azure-*.actions.githubusercontent.com` | GET | `*/idtoken/*` | OIDC token | essential |
| `run-actions-*-azure-*.actions.githubusercontent.com` | POST | `*/renewjob`, `*/completejob` | job lease and completion | essential |
| `results-receiver.actions.githubusercontent.com` | POST | `/twirp/*` | artifact, cache and step-status calls | optional |
| `productionresultssa*.blob.core.windows.net` | GET, HEAD, PUT | `/actions-results/*`, `/actions-cache/*` | artifact, log and cache blobs | optional |

- **Essential** endpoints are always allowed on a filtered host. The job cannot run without them.
- An **optional** endpoint is allowed only if none of your rules for that host matches the
  request. Your own rule, including `NONE`, takes priority.
- The job summary shows how many essential endpoints apply to the hosts that you filter.
- `allow-github-platform: false` turns all of this off. You must then allow the endpoints
  yourself.

Endpoints that a workflow chooses to use are not on the list. For example, a code-scanning job
that uploads SARIF must add `"*/code-scanning/sarifs": POST` on `api.github.com`.

### Limits of `http-filter`

- **It applies only to traffic that the proxy decrypts.** Hosts in `passthrough-domains` and
  HTTPS from containers are checked by name only, so the proxy cannot see their paths.
- **It does not check request bodies or query strings.** A filter limits where and how a step can
  write. It cannot stop data hidden inside an allowed write to an allowed path, or a small amount
  of data in a path or query.
- **Some uploads go to a separate storage host,** for example git LFS objects, and registries
  that redirect uploads. Filter that host too.
