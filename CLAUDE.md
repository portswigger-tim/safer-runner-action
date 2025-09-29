# CLAUDE.md - Developer Guide for Safer Runner Action

This guide helps developers understand, maintain, and extend the Safer Runner Action codebase.

## 🏗️ Architecture Overview

### Core Components

```
src/
├── main.ts          # Main action entry point - sets up security layers
├── post.ts          # Post-action analysis and reporting
├── validation.ts    # System integrity validation with SHA256 checksums
└── validation.test.ts # Tests for validation system
```

### Build Process

```bash
npm run build        # Builds main.ts -> dist/main.js
npm run build:post   # Builds post.ts -> dist/post.js
npm run package      # Clean + build both + run tests
```

**Critical**: Always run both builds and commit `dist/*.js` files - GitHub Actions executes the compiled versions, not the TypeScript source.

## 🛡️ Security Architecture

### Two-Layer Protection Model

1. **DNS Layer (DNSmasq)** - `main.ts:88-134`
   - Blocks domain resolution for unauthorized domains
   - Returns `NXDOMAIN` for blocked domains
   - Uses Quad9 (9.9.9.9) for allowed domains

2. **Network Layer (iptables)** - `main.ts:43-66`
   - Blocks connections to unauthorized IP addresses
   - Uses `ipset` for efficient IP allowlists
   - Logs all connection attempts for analysis

### Validation System - `validation.ts`

**Purpose**: Detects tampering with security configurations during workflow execution

**Flow**:
1. **Post-setup baseline** - Capture checksums after security setup complete
2. **User workflow runs** - Potentially malicious code could execute
3. **Post-action verification** - Compare current state to baseline

**Monitored Files**:
- `/etc/dnsmasq.conf` - DNS filtering rules
- `/etc/resolv.conf` - DNS resolver configuration
- `/etc/systemd/resolved.conf.d/no-stub.conf` - systemd DNS config
- `iptables` chains (INPUT, OUTPUT, FORWARD) - Firewall rules

## 📊 Summary Generation - `post.ts`

### Enhanced Summary Structure

The summary correlates DNS resolutions with actual network connections to show the complete security picture.

#### Key Functions

**`correlateDomainConnections()`** - Lines 532-576
- Maps IP addresses back to domain names
- Correlates DNS resolutions with actual connections
- Handles multiple IPs per domain
- Priority: DENIED > ALLOWED > ANALYZED

**`generateDomainAccessDetails()`** - Lines 442-487
- Creates four-column correlation table
- Shows DNS status vs connection status
- Infers domain purposes (API, CDN, Auth, etc.)
- Collapses GitHub infrastructure to reduce noise

**`generateThreatDetails()`** - Lines 490-541
- Separates DNS filtering from firewall blocking
- Shows domain context for blocked IP connections
- Explains two-layer protection model

#### Summary Sections (in order)
1. **Executive Summary** - Security status at-a-glance
2. **Network Activity Summary** - Key metrics table
3. **External Domains Accessed** - Four-column correlation table
4. **GitHub Infrastructure** - Collapsed details
5. **Security Events** - Threat detection (DNS + firewall)
6. **System Integrity Report** - Validation results
7. **Configuration Suggestions** - For analyze mode

## 🔧 Development Workflows

### Making Changes

1. **Modify source** - Edit `src/*.ts` files
2. **Build & test** - `npm run package`
3. **Test locally** - Use validation test: `node src/validation.test.ts`
4. **Commit source + dist** - Always commit both `.ts` and `.js` files
5. **Test in GitHub Actions** - Use the test workflow

### Adding New Security Features

1. **DNS filtering** - Modify `setupDNSMasq()` in `main.ts`
2. **Firewall rules** - Modify `setupFirewallRules()` in `main.ts`
3. **Validation** - Add new files/rules to `validation.ts`
4. **Reporting** - Enhance correlation logic in `post.ts`

### Debugging

#### Local Testing
```bash
# Test validation system
node lib/validation.test.ts

# Check TypeScript compilation
npx tsc --noEmit

# Build and check file sizes
npm run package
ls -la dist/
```

#### GitHub Actions Debugging
- Check job summary for network access report
- Review system logs: `sudo grep -E 'Processing: |GitHub-Allow: |User-Allow: |Drop-Enforce: ' /var/log/syslog`
- Validate DNS: `dig @127.0.0.1 example.com`
- Check iptables: `sudo iptables -L OUTPUT -n --line-numbers`

## 🧪 Testing Strategy

### Automated Tests - `.github/workflows/test.yml`

1. **test-analyze-mode** - Network monitoring without blocking
2. **test-enforce-mode** - Active threat blocking
3. **test-github-actions-compatibility** - GitHub Actions integration
4. **test-edge-cases** - DNS resolution, localhost, direct IPs
5. **test-system-integrity** - Validation system with Falco integration

### Manual Testing Scenarios

```bash
# Test DNS blocking
timeout 5 curl https://malicious-domain.com  # Should fail in enforce mode

# Test allowed domains
curl https://api.github.com/user  # Should always work

# Test validation tampering
echo "# TEST" | sudo tee -a /etc/dnsmasq.conf  # Should be detected
```

## 🚨 Security Considerations

### Limitations & Workarounds

The README documents potential attack vectors:
1. **Data exfiltration via allowed domains** - Abuse GitHub/npm for data theft
2. **DNS tunneling** - Encode data in DNS queries
3. **Local file system attacks** - Stage data for later exfiltration
4. **Process/system call abuse** - Container escapes, privilege escalation

### Defense in Depth

Network filtering is **first line of defense**. Recommended complementary tools:
- **Falco** - Runtime security monitoring
- **Container security** - Distroless images, read-only filesystems
- **Dependency scanning** - Snyk, Dependabot
- **SIEM integration** - Log forwarding and analysis

## 📝 Common Tasks

### Update GitHub Required Domains

**Files**: `main.ts:104-116` and `post.ts:237-251`
```typescript
const githubDomains = [
  'github.com', 'actions.githubusercontent.com', // etc
  // Add new domain here
  'new.github.domain.com'
];
```

### Add New Domain Purpose Recognition

**File**: `post.ts:507-530`
```typescript
function inferDomainPurpose(domain: string): string {
  if (domain.includes('api.')) return '🔗 API Service';
  // Add new pattern here
  if (domain.includes('webhook.')) return '🔔 Webhook Service';
  return '🌐 External Service';
}
```

### Enhance Validation

**File**: `validation.ts:44-48`
```typescript
const criticalFiles = [
  '/etc/dnsmasq.conf',
  '/etc/resolv.conf',
  // Add new file to monitor
  '/etc/new-security-file.conf'
];
```

## 📚 Key Dependencies

- `@actions/core` - GitHub Actions runtime
- `@actions/exec` - Command execution
- `crypto` - SHA256 checksums for validation
- `fs` - File system operations

## 🐛 Troubleshooting

### Build Issues
- Ensure TypeScript compiles: `npx tsc --noEmit`
- Check for missing dependencies: `npm install`
- Verify file paths are absolute in imports

### Runtime Issues
- DNS not working: Check `/etc/resolv.conf` points to `127.0.0.1`
- Connections blocked unexpectedly: Check `ipset list github` and `ipset list user`
- Validation failures: Check if files exist and permissions are correct

### Integration Issues
- Summary not showing: Verify `dist/post.js` is updated and committed
- GitHub Actions failing: Check action.yml syntax and file paths
- Falco integration: Ensure pinned commit SHA is valid

## 🚀 Future Enhancements

### Potential Improvements

1. **Smart DNS caching** - Cache DNS responses to reduce lookup time
2. **Machine learning anomaly detection** - Detect unusual network patterns
3. **Integration with more security tools** - Snyk, Semgrep, etc.
4. **Custom rule engine** - User-defined security policies
5. **Real-time alerting** - Slack/email notifications for threats
6. **Performance optimization** - Reduce startup time and resource usage

### Architecture Considerations

- **Modularization** - Split main.ts into focused modules
- **Configuration system** - YAML-based security policies
- **Plugin architecture** - Extensible security modules
- **Telemetry** - Anonymous usage analytics for improvement

---

## 💡 Pro Tips

1. **Always test both modes** - Analyze and enforce behave differently
2. **Watch file sizes** - Large dist files indicate potential issues
3. **Monitor performance** - DNS/iptables rules affect startup time
4. **Update regularly** - GitHub domains change frequently
5. **Use validation** - System integrity checks catch tampering
6. **Read logs carefully** - iptables logs show exactly what was blocked
7. **Test edge cases** - Direct IPs, localhost, CNAME records
8. **Document changes** - Update this file when making significant modifications

## 📞 Getting Help

- **GitHub Issues** - Bug reports and feature requests
- **Code Review** - Use test workflow to validate changes
- **Documentation** - README.md for user-facing docs
- **Security** - Follow responsible disclosure for security issues

Remember: This action protects against supply chain attacks. Changes should be thoroughly tested and reviewed for security implications.