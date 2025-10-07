# Safer Runner Action

Multi-layer security for GitHub Actions runners with network filtering (DNS + iptables), privilege control (sudo management), and integrity validation (tampering detection). Implements default-deny policy with comprehensive security reporting.

## Who This Is For

### ✅ Use This Action If You:

- **Run untrusted code** in GitHub Actions (open source projects accepting PRs from external contributors)
- **Use third-party actions** and want visibility into their network activity
- **Accept community contributions** and need supply chain attack protection
- **Build open source software** with dependencies from npm, PyPI, or other package registries
- **Need compliance evidence** showing network access controls and audit trails
- **Use GitHub-hosted Ubuntu runners** (ubuntu-latest, ubuntu-22.04, ubuntu-20.04)
- **Want security observability** before committing to enforcement (analyze mode)

### ❌ This Action Is NOT For You If:

- **You only run trusted, first-party code** with no external dependencies
- **You use Windows or macOS runners** (Linux/Ubuntu only)
- **Your jobs run in containers** (`container:` in workflow - sudo access conflicts)
- **You use self-hosted non-Ubuntu runners** (RHEL, Debian, etc. - not currently supported)
- **Your workflow requires unrestricted network access** to arbitrary domains
- **You need sub-second performance** (adds ~2-5s overhead for security setup)
- **You want protection against sophisticated attackers** using allowed domain abuse (this is first-line defense only)

### 💡 Common Use Cases

**Open Source Maintainers**: Protect against malicious PRs that install compromised dependencies attempting to exfiltrate repository secrets or tokens.

**Enterprise CI/CD**: Add network observability and control to GitHub Actions workflows handling sensitive data or credentials.

**Security Compliance**: Generate audit trails showing network access controls were enforced during builds and deployments.

**Dependency Analysis**: Use analyze mode to understand what external services your build dependencies are contacting.

## Features

- **Dual modes**: `analyze` (monitoring) or `enforce` (blocking)
- **DNS filtering**: DNSMasq with Quad9 upstream resolver
- **Firewall rules**: iptables prevents DNS bypass via direct IP connections
- **Sudo logging**: All sudo usage logged to `/var/log/safer-runner/main-sudo.log`
- **Sudo disabling**: Optionally disable sudo access after setup (prevents privilege escalation)
- **Docker disabling**: Optionally disable Docker access (prevents container escape attacks)
- **Custom domains**: Add trusted domains via input parameter
- **Automatic reporting**: Network access provenance in job summaries
- **Risky subdomain blocking**: Blocks gist.github.com and raw.githubusercontent.com by default in enforce mode

## Usage

⚠️ **Important**: Always place this action as the **first step** in your workflow to maximize security coverage.

ℹ️ **How it works**: This action uses a `pre` hook to establish security monitoring in analyze mode before any workflow steps run, then the main action applies your desired configuration (analyze or enforce mode).

### Analyze mode (default)

```yaml
steps:
  - uses: portswigger-tim/safer-runner-action@051c15b702704d3a144049cc992714a4997d107c # v1.1.0
  - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
  - run: |
      curl https://example.com  # Logged but not blocked
```

### Enforce mode

```yaml
steps:
  - uses: portswigger-tim/safer-runner-action@051c15b702704d3a144049cc992714a4997d107c # v1.1.0
    with:
      mode: 'enforce'
      allowed-domains: |
        example.com
        api.trusted-service.com
  - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
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
| `disable-sudo` | Disable sudo access for runner user after setup | `false` |
| `sudo-config` | Custom sudoers configuration for runner user (multi-line string) | `''` |
| `disable-docker` | Remove runner user from docker group (prevents container usage) | `false` |

## Network Access Reports

Job summaries include a Network Access Provenance table showing:

- Domain/IP addresses accessed
- Ports used
- Status (✅ Allowed, ❌ Denied, 📊 Analyzed)
- Source (GitHub Required, User Defined)

In analyze mode, the report suggests an `allowed-domains` configuration based on non-GitHub domains accessed, making it easy to transition to enforce mode.

## Security Model

This action implements multi-layer security with DNS filtering, firewall rules, and privilege control. GitHub Actions required domains are automatically allowed. Sudo usage is always logged for auditability.

### Privilege Control (Optional)

Control sudo and Docker access to prevent privilege escalation and container escape attacks:

```yaml
steps:
  - uses: portswigger-tim/safer-runner-action@051c15b702704d3a144049cc992714a4997d107c # v1.1.0
    with:
      mode: 'enforce'
      disable-sudo: 'true'    # Prevents sudo usage after setup
      disable-docker: 'true'  # Prevents Docker/container usage
      allowed-domains: |
        registry.npmjs.org
  - run: npm ci && npm test   # ✅ Works without elevated privileges
  - run: sudo apt install x   # ❌ Fails (sudo disabled)
  - run: docker build .       # ❌ Fails (Docker disabled)
```

**Note**: Only disable sudo/Docker if your workflow doesn't require them. These are advanced security features that prevent malicious code from bypassing security controls.

## Limitations

### Platform Support

- **GitHub-hosted runners**: Only Ubuntu runners are supported. Windows and macOS runners are not supported.
- **Self-hosted runners**: Only Ubuntu runners with sudo access and iptables support. Other Linux distributions (RHEL, Debian, etc.) and Windows/macOS runners are not supported.
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
# DNS logs (no sudo required)
cat /var/log/safer-runner/pre-dns.log      # Pre-hook DNS activity
cat /var/log/safer-runner/main-dns.log     # Main action DNS activity

# Network logs (no sudo required)
cat /var/log/safer-runner/pre-iptables.log  # Pre-hook network activity
cat /var/log/safer-runner/main-iptables.log # Main action network activity

# Sudo logs (no sudo required)
cat /var/log/safer-runner/pre-sudo.log      # Pre-hook sudo commands
cat /var/log/safer-runner/main-sudo.log     # Main action sudo commands
```

## License

This action is provided as-is for defensive security purposes.
