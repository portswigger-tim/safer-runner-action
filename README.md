# PortSwigger GitHub Actions

A collection of security-focused GitHub Actions for safer CI/CD workflows.

## Actions

### 🛡️ [Safer Runner](./safer-runner/)

Adds network security layer to GitHub Actions runners with DNS filtering and firewall rules.

- **DNS Filtering**: Quad9 malware blocking with 98% threat coverage
- **Dual Modes**: `analyze` (monitoring) and `enforce` (blocking)
- **GitHub Compatible**: Pre-configured with all required GitHub domains
- **Custom Domains**: Support for allowlisting additional trusted domains

```yaml
- uses: portswigger-tim/safer-runner-action/safer-runner@v1
  with:
    mode: 'enforce'
    allowed-domains: 'registry.npmjs.org pypi.org'
```

[📖 Full Documentation](./safer-runner/README.md)

---

## Usage in Your Workflows

Each action is located in its own subdirectory. Reference them using the full path:

```yaml
# Use the safer-runner action
- uses: portswigger-tim/safer-runner-action/safer-runner@v1

# Future actions will follow the same pattern
# - uses: portswigger-tim/safer-runner-action/another-action@v1
```

## Contributing

This repository contains defensive security tools only. All actions are designed to:

- **Enhance Security**: Add protective layers to CI/CD workflows
- **Maintain Compatibility**: Work seamlessly with existing GitHub Actions
- **Provide Visibility**: Log security events for analysis
- **Follow Best Practices**: Implement security controls without breaking workflows

## License

All actions are provided as-is for defensive security purposes.
