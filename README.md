# Safer Runner Action

A GitHub composite action that adds a network security layer to GitHub Actions runners through DNS filtering and iptables rules. This action prevents communication with malicious domains by implementing a default-deny DNS policy and allowing only explicitly permitted domains.

## Features

- **Dual Operation Modes**: `analyze` mode for traffic monitoring, `enforce` mode for active blocking
- **DNS Filtering**: Uses DNSMasq with Quad9 (9.9.9.9) - 98% malware blocking with real-time threat intelligence
- **Firewall Rules**: Configures iptables to control outbound network traffic
- **GitHub Actions Compatible**: Pre-configured to allow all required GitHub domains
- **Custom Domain Support**: Add your own trusted domains via input parameters
- **Automatic Log Analysis**: Automatic network access provenance reports after each run
- **Supply Chain Protection**: Helps defend against malicious network requests in compromised dependencies

## Usage

### Basic Usage (Analyze Mode)

```yaml
steps:
  - uses: portswigger-tim/safer-runner-action@v1
    # Default mode is "analyze" - logs traffic without blocking
  - name: Your workflow steps
    run: |
      # Your commands here - all traffic allowed but logged
      curl https://api.github.com/user
      curl https://example.com  # This will be logged but not blocked
```

### Enforce Mode (Blocking)

```yaml
steps:
  - uses: portswigger-tim/safer-runner-action@v1
    with:
      mode: 'enforce'
      allowed-domains: >-
        example.com
        api.trusted-service.com
        cdn.example.org

  - name: Your secure workflow
    run: |
      # Only allowed domains are accessible
      curl https://api.github.com/user  # ✅ Allowed (GitHub domain)
      curl https://api.trusted-service.com/data  # ✅ Allowed (custom domain)
      curl https://malicious.com  # ❌ Blocked (not in allowed list)
```

### Custom Configuration

```yaml
steps:
  - uses: portswigger-tim/safer-runner-action@v1
    with:
      mode: 'analyze'  # or 'enforce'
      allowed-domains: >-
        example.com
        api.trusted-service.com
        registry.npmjs.org
        pypi.org

  - name: Your workflow
    run: |
      # Behavior depends on mode setting
      curl https://api.trusted-service.com/data
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `mode` | Operation mode: `analyze` logs traffic without blocking, `enforce` blocks unauthorized domains | No | `analyze` |
| `allowed-domains` | Space-separated list of additional domains to allow (beyond GitHub required domains) | No | `''` |

## Pre-configured GitHub Domains

The action automatically allows all GitHub Actions required domains:

**Essential Operations:**
- `github.com` - Main GitHub service
- `actions.githubusercontent.com` - Actions runtime
- `api.github.com` - GitHub API

**Actions & Packages:**
- `codeload.github.com` - Code downloads
- `pkg.actions.githubusercontent.com` - Action packages
- `pkg.github.com` - GitHub packages
- `pkg-containers.githubusercontent.com` - Container packages
- `ghcr.io` - GitHub Container Registry

**Artifacts & Storage:**
- `results-receiver.actions.githubusercontent.com` - Results upload
- `productionresultssa0-19.blob.core.windows.net` - GitHub's specific Azure storage accounts (20 accounts)
- `github-cloud.githubusercontent.com` - Git LFS
- `github-cloud.s3.amazonaws.com` - Git LFS storage

**Runner Updates:**
- `objects.githubusercontent.com` - Runner binaries
- `objects-origin.githubusercontent.com` - Origin server
- `github-releases.githubusercontent.com` - Release files
- `github-registry-files.githubusercontent.com` - Registry files

**Additional Services:**
- `dependabot-actions.githubapp.com` - Dependabot actions
- `release-assets.githubusercontent.com` - Release assets
- `api.snapcraft.io` - Snapcraft integration

## How It Works

1. **Install Dependencies**: Installs `dnsmasq` and `ipset` packages
2. **Configure Firewall**: Sets up iptables rules to control outbound traffic
3. **DNS Configuration**: Configures system DNS to use local DNSMasq instance
4. **DNSMasq Setup**: Configures DNS policy with Quad9 (9.9.9.9) upstream for malware protection
5. **Service Startup**: Starts DNSMasq and applies final security rules
6. **Automatic Analysis**: Post-action analyzes logs and generates network access summary

## Network Access Reports

The action automatically generates a **Network Access Provenance** table in your job summary showing:

- **Domain/IP addresses** accessed during the workflow
- **Ports** used for connections
- **Status** (✅ Allowed, ❌ Denied, 📊 Analyzed)
- **Source** (GitHub Required, User Defined, etc.)
- **Summary statistics** of connection attempts

**Analyze Mode Bonus**: Automatically suggests an `allowed-domains` configuration based on the non-GitHub domains accessed during your run, making it easy to transition to enforce mode.

No configuration needed - the report appears automatically after each run!

## Security Model

### Analyze Mode
- **Traffic Monitoring**: All DNS queries are logged but allowed to proceed
- **Comprehensive Logging**: DNS queries, firewall activity, and connection attempts are logged
- **Non-Blocking**: Workflow continues normally while collecting security intelligence

### Enforce Mode
- **Default Deny**: All DNS queries return NXDOMAIN unless explicitly allowed
- **Firewall Protection**: iptables rules prevent bypassing DNS filtering
- **Strict Blocking**: Only allowed domains can be accessed

### Both Modes
- **Azure Metadata**: Preserves access to Azure metadata service (required for GitHub Actions)
- **Established Connections**: Allows return traffic for established connections

## Debugging

You can check DNS and firewall logs:

```bash
# View recent DNS queries and firewall actions
sudo grep -E 'Processing: |GitHub-Allow: |User-Allow: |Drop-Enforce: |Allow-Analyze: ' /var/log/syslog
```

## Supply Chain Security Context

GitHub Actions supply chain attacks have increased significantly, with several major incidents in 2024-2025 affecting thousands of repositories. These attacks often follow a pattern:

1. **Compromise**: Malicious code gets injected through compromised dependencies, PR injections, or compromised GitHub Actions
2. **Network Exfiltration**: The malicious code makes HTTP requests to attacker-controlled domains to steal secrets, tokens, or sensitive data
3. **Persistence**: Attackers use stolen credentials to maintain access or compromise additional repositories

### Real-World Protection

This action provides network-level defense against such attacks by:

- **Blocking data exfiltration** to unauthorized domains in enforce mode
- **Detecting suspicious activity** through comprehensive DNS and network logging in analyze mode
- **Preventing malicious downloads** by controlling which domains can be accessed

**Note**: This action focuses on network-level protection and should be part of a comprehensive security strategy that includes action pinning, input validation, and minimal permissions.

### Recent Attack Examples

- **tj-actions/changed-files (CVE-2025-30066)**: Affected 23,000+ repositories through malicious Python script downloads that would have been blocked by network filtering
- **s1ngularity attack**: Used malicious network requests to exfiltrate data to attacker-controlled repositories
- **Shai-Hulud worm**: Self-replicated through network-based communication that could have been detected and blocked

## Limitations and Attacker Workarounds

While this action provides strong network-level protection, sophisticated attackers may attempt workarounds. **Network filtering alone is not sufficient** - combine with additional runtime security tooling:

### Potential Attack Vectors

**🚨 Data Exfiltration via Allowed Domains**
- Attackers could abuse legitimate allowed domains (GitHub, npm, PyPI) to exfiltrate data
- Example: Uploading secrets to a public repository or package registry
- **Mitigation**: Use runtime monitoring to detect unusual data patterns

**🚨 DNS Tunneling and Alternative Protocols**
- Advanced attackers might use DNS queries to encode and exfiltrate data
- Non-HTTP protocols (raw sockets, custom ports) could bypass HTTP-focused filtering
- **Mitigation**: Comprehensive network monitoring and anomaly detection

**🚨 Local File System Attacks**
- Malicious code could write sensitive data to shared file systems or container volumes
- Data could be staged for later exfiltration by other processes
- **Mitigation**: File system monitoring and access controls

**🚨 Process and System Call Abuse**
- Attackers might attempt privilege escalation or container escapes
- System resource abuse (CPU, memory) for cryptocurrency mining
- **Mitigation**: Runtime behavior analysis and system call monitoring

### Recommended Complementary Tooling

**🛡️ Falco for Runtime Security**
```yaml
- name: Runtime Security with Falco
  uses: falcosecurity/falco-action@v1
  with:
    rules: |
      - rule: Detect Sensitive File Access
        desc: Detect access to sensitive files
        condition: >
          open_read and fd.filename in (/etc/passwd, /etc/shadow, /home/*/.ssh/*, /root/.ssh/*)
        output: Sensitive file accessed (user=%user.name command=%proc.cmdline file=%fd.name)
        priority: WARNING

      - rule: Unexpected Network Activity
        desc: Detect unusual network connections
        condition: >
          inbound or outbound and not fd.net.cip in (github_ips, allowed_ips)
        output: Unexpected network activity (user=%user.name command=%proc.cmdline connection=%fd.net.cip.name:%fd.net.sport->%fd.net.sip.name:%fd.net.dport)
        priority: WARNING

      - rule: Suspicious Process Execution
        desc: Detect potentially malicious process execution
        condition: >
          spawned_process and (proc.name in (nc, ncat, socat, wget, curl) and proc.args contains "shell")
        output: Suspicious process execution (user=%user.name command=%proc.cmdline)
        priority: CRITICAL
```

**🛡️ Additional Security Layers**
- **Container Security**: Use distroless images, read-only filesystems, non-root users
- **Secrets Management**: Use GitHub's native secrets, avoid hardcoded credentials
- **Dependency Scanning**: Tools like Snyk, Dependabot, or GitHub's native scanning
- **Action Security**: Pin actions to specific commits, use trusted publishers only
- **SIEM Integration**: Forward logs to security information and event management systems

### Defense in Depth Strategy

```yaml
# Example comprehensive security workflow
steps:
  # Layer 1: Network Security
  - uses: portswigger-tim/safer-runner-action@v1
    with:
      mode: 'enforce'
      allowed-domains: 'api.trusted-service.com'

  # Layer 2: Runtime Security
  - uses: falcosecurity/falco-action@v1
    with:
      rules_file: .github/falco-rules.yaml

  # Layer 3: Container Security
  - uses: securecodewarrior/github-action-add-sarif@v1
    with:
      sarif-file: container-scan-results.sarif

  # Layer 4: Your Application
  - name: Run application with minimal privileges
    run: |
      # Your secure application logic
    env:
      # Use GitHub secrets, never hardcode
      API_KEY: ${{ secrets.API_KEY }}
```

**Remember**: Network filtering is your first line of defense, but attackers adapt. Combine multiple security layers for maximum protection.

## Debugging

You can check DNS and firewall logs:

```bash
# View recent DNS queries and firewall actions
sudo grep -E 'Processing: |GitHub-Allow: |User-Allow: |Drop-Enforce: |Allow-Analyze: ' /var/log/syslog
```

## License

This action is provided as-is for defensive security purposes.