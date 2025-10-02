# Safer Runner Action

Network security layer for GitHub Actions runners using DNS filtering (Quad9) and iptables rules. Implements default-deny policy: only explicitly permitted domains are accessible.

## Features

- **Dual modes**: `analyze` (monitoring) or `enforce` (blocking)
- **DNS filtering**: DNSMasq with Quad9 upstream resolver
- **Firewall rules**: iptables prevents DNS bypass via direct IP connections
- **Custom domains**: Add trusted domains via input parameter
- **Automatic reporting**: Network access provenance in job summaries
- **Risky subdomain blocking**: Blocks gist.github.com and raw.githubusercontent.com by default in enforce mode

## Usage

⚠️ **Important**: Always place this action as the **first step** in your workflow to maximize security coverage.

ℹ️ **How it works**: This action uses a `pre` hook to establish security monitoring in analyze mode before any workflow steps run, then the main action applies your desired configuration (analyze or enforce mode).

### Analyze mode (default)

```yaml
steps:
  - uses: portswigger-tim/safer-runner-action@v1  # Must be first step
  - uses: actions/checkout@v4
  - run: |
      curl https://example.com  # Logged but not blocked
```

### Enforce mode

```yaml
steps:
  - uses: portswigger-tim/safer-runner-action@v1  # Must be first step
    with:
      mode: 'enforce'
      allowed-domains: |
        example.com
        api.trusted-service.com
  - uses: actions/checkout@v4
  - run: |
      curl https://api.trusted-service.com  # ✅ Allowed
      curl https://malicious.com  # ❌ Blocked
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `mode` | `analyze` (log only) or `enforce` (block) | `analyze` |
| `allowed-domains` | Additional domains to allow | `''` |
| `fail-on-tampering` | Fail workflow if security config is tampered | `false` |
| `block-risky-github-subdomains` | Block gist.github.com and raw.githubusercontent.com in enforce mode | `true` |

## How It Works

1. Installs `dnsmasq` and `ipset` packages
2. Configures iptables rules to control outbound traffic
3. Configures system DNS to use local DNSMasq instance
4. Sets up DNS policy with Quad9 upstream resolver
5. Starts DNSMasq and applies security rules
6. Post-action analyzes logs and generates network access report

GitHub Actions required domains are pre-configured and automatically allowed.

## Network Access Reports

Job summaries include a Network Access Provenance table showing:

- Domain/IP addresses accessed
- Ports used
- Status (✅ Allowed, ❌ Denied, 📊 Analyzed)
- Source (GitHub Required, User Defined)

In analyze mode, the report suggests an `allowed-domains` configuration based on non-GitHub domains accessed, making it easy to transition to enforce mode.

## Security Model

### Analyze Mode
- All DNS queries logged but allowed
- DNS queries, firewall activity, and connection attempts are logged
- Workflow continues normally while collecting security intelligence

### Enforce Mode
- All DNS queries return NXDOMAIN unless explicitly allowed
- iptables rules prevent bypassing DNS filtering
- Only allowed domains accessible

### Both Modes
- Azure metadata service access preserved (required for GitHub Actions)
- Return traffic for established connections allowed

## Limitations

### Platform Support

- **GitHub-hosted runners**: Only Ubuntu runners are supported. Windows and macOS runners are not supported.
- **Self-hosted runners**: Linux runners with sudo access and iptables support. Windows and macOS runners are not supported.
- **Containerized jobs**: Not supported when the job runs in a container due to sudo access requirements.

### Security Limitations

Network filtering provides a first line of defense but has limitations:

#### Timing Window
- **Pre-hook ordering**: This action's `pre:` hook establishes analyze mode monitoring before the main action step runs, providing early visibility
- **Other actions' pre-hooks**: Actions that appear later in the workflow will have their `pre:` hooks run after this action's pre-hook, so they are monitored
- **Actions before this one**: Any actions placed before this action in the workflow will have their `pre:` hooks run before monitoring is established
- **Mitigation**: Place this action as the first step in your workflow and carefully vet all actions used

#### Attack Vectors
- **Data exfiltration via allowed domains**: Abuse GitHub/npm/PyPI to upload secrets
- **Local file system attacks**: Stage data for later exfiltration
- **Process/system call abuse**: Container escapes, privilege escalation

### Defense in Depth

Combine with additional security layers:

- **Runtime security**: Falco, Tracee
- **Container security**: Distroless images, read-only filesystems, non-root users
- **Secrets management**: GitHub secrets, secure credential handling
- **Dependency scanning**: Snyk, Dependabot, GitHub native scanning
- **Action security**: Pin to commits, use trusted publishers

## Debugging

View DNS and firewall logs:

```bash
sudo grep -E 'Processing: |GitHub-Allow: |User-Allow: |Drop-Enforce: |Allow-Analyze: ' /var/log/syslog
```

## License

This action is provided as-is for defensive security purposes.
