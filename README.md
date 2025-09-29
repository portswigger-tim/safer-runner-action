# Safer Runner Action

A GitHub composite action that adds a network security layer to GitHub Actions runners through DNS filtering and iptables rules. This action prevents communication with malicious domains by implementing a default-deny DNS policy and allowing only explicitly permitted domains.

## Features

- **Dual Operation Modes**: `analyze` mode for traffic monitoring, `enforce` mode for active blocking
- **DNS Filtering**: Uses DNSMasq with Quad9 (9.9.9.9) - 98% malware blocking with real-time threat intelligence
- **Firewall Rules**: Configures iptables to control outbound network traffic
- **GitHub Actions Compatible**: Pre-configured to allow all required GitHub domains
- **Custom Domain Support**: Add your own trusted domains via input parameters
- **Automatic Log Analysis**: Automatic network access provenance reports after each run

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

## License

This action is provided as-is for defensive security purposes.