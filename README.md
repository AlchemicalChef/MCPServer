# vuln-scanner-mcp

A comprehensive Model Context Protocol (MCP) server for security vulnerability scanning, analysis, and research. Designed to integrate with Claude and other MCP-compatible AI assistants.

## Features

- **17 Security Tools** - Static analysis, secret detection, dependency scanning, and more
- **6 Knowledge Resources** - OWASP Top 10, CWE references, remediation guides
- **6 Prompt Templates** - Security audits, threat modeling, incident response
- **Comprehensive Audit Logging** - Track all tool invocations with formal model generation
- **Multi-Language Support** - JavaScript, TypeScript, Python, Go, PHP, Ruby

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vuln-scanner-mcp.git
cd vuln-scanner-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Usage

### With Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vuln-scanner": {
      "command": "node",
      "args": ["/path/to/vuln-scanner-mcp/build/index.js"]
    }
  }
}
```

### Standalone

```bash
# Run the server
npm start

# Development mode (watch for changes)
npm run dev

# Inspect with MCP Inspector
npm run inspect
```

## Tools

### Security Scanning

| Tool | Description |
|------|-------------|
| `scan-code` | Static analysis for security vulnerabilities (SAST) |
| `scan-secrets` | Detect hardcoded secrets with entropy analysis |
| `scan-dependencies` | Check dependencies for known vulnerabilities |
| `scan-iac` | Infrastructure as Code security scanning |
| `scan-licenses` | License compliance and risk analysis |
| `scan-api-spec` | OpenAPI/Swagger specification security review |
| `scan-git-history` | Scan git history for leaked secrets |

### Analysis Tools

| Tool | Description |
|------|-------------|
| `analyze-headers` | HTTP security header analysis |
| `analyze-dataflow` | Taint tracking and data flow analysis |
| `analyze-attack-surface` | Map entry points, sinks, and trust boundaries |
| `calculate-cvss` | CVSS v3.1 score calculation with presets |

### Output & Reporting

| Tool | Description |
|------|-------------|
| `export-sarif` | Export findings in SARIF format |
| `generate-sbom` | Generate Software Bill of Materials |
| `generate-formal-model` | Generate TLA+, Alloy, state machines from code |
| `model-audit-trail` | Generate formal models from audit history |

### Research Tools (Authorized Use Only)

| Tool | Description |
|------|-------------|
| `inject-debugger` | Debug payload injection for security research |
| `generate-payloads` | Context-aware security testing payloads |

## Resources

Knowledge bases available via MCP resources:

- **owasp-top-10** - OWASP Top 10 vulnerability reference
- **cwe-reference** - Common Weakness Enumeration database
- **vulnerability-patterns** - Language-specific vulnerability patterns
- **compliance-mapping** - Security compliance framework mappings
- **remediation-guides** - Vulnerability fix recommendations
- **security-benchmarks** - Security configuration benchmarks

## Prompts

Pre-built prompt templates for common workflows:

- **security-audit** - Comprehensive security audit workflow
- **threat-model** - STRIDE-based threat modeling
- **vulnerability-report** - Professional vulnerability reporting
- **incident-response** - Incident response playbook
- **secure-code-fix** - Secure code remediation guidance
- **compliance-assessment** - Compliance gap analysis

## Configuration

### Audit Logging

The server logs all tool invocations for security review:

```typescript
{
  auditLog: {
    enabled: true,
    logFile: './mcp-audit.log',
    consoleOutput: false,
    level: 'standard',  // 'minimal' | 'standard' | 'verbose'
    maxFileSize: 10485760,  // 10MB
    redactSensitive: true,
    sensitiveFields: ['password', 'secret', 'token', 'key', 'apiKey']
  }
}
```

### Formal Model Generation

Generate formal specifications from audit trails:

```
model-audit-trail --modelType=state-machine
model-audit-trail --modelType=tlaplus
model-audit-trail --modelType=alloy
model-audit-trail --modelType=petri-net
model-audit-trail --modelType=sequence
```

## Example Usage

### Scan Code for Vulnerabilities

```
Use the scan-code tool to analyze src/ for security issues
```

### Generate CVSS Score

```
Calculate CVSS score for a vulnerability with:
- Network attack vector
- Low complexity
- No privileges required
- High confidentiality impact
```

### Analyze Attack Surface

```
Use analyze-attack-surface on the API routes to identify entry points and dangerous sinks
```

### Export to SARIF

```
Export all findings to SARIF format for integration with GitHub Advanced Security
```

## Project Structure

```
src/
├── index.ts           # Entry point
├── server.ts          # Server factory
├── tools/             # 17 security tools
│   ├── index.ts       # Tool registration
│   ├── scanCode.ts
│   ├── scanSecrets.ts
│   └── ...
├── resources/         # 6 knowledge bases
│   ├── index.ts
│   ├── owaspTop10.ts
│   └── ...
├── prompts/           # 6 prompt templates
│   ├── index.ts
│   ├── securityAudit.ts
│   └── ...
├── types/             # Shared TypeScript types
└── utils/
    ├── auditLog.ts    # Audit logging + formal models
    └── sanitize.ts    # Input sanitization
```

## Security Considerations

- **Research Tools**: `inject-debugger` and `generate-payloads` are for authorized security research only
- **Audit Logging**: All tool invocations are logged by default
- **Input Sanitization**: All inputs are validated and sanitized
- **Sensitive Data Redaction**: Secrets are automatically redacted from logs

## Requirements

- Node.js >= 18.0.0
- TypeScript >= 5.3.0

## License

ISC

## Contributing

Contributions welcome! Please ensure all security tools are used responsibly and ethically.
