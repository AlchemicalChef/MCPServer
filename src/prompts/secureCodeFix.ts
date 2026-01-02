import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerSecureCodeFixPrompt(server: McpServer): void {
  server.prompt(
    'secure-code-fix',
    'Generate secure code replacements for vulnerable code snippets',
    {
      vulnerableCode: z.string().describe('The vulnerable code snippet to fix'),
      language: z.enum(['javascript', 'typescript', 'python', 'go', 'java', 'c', 'cpp', 'rust', 'php', 'ruby', 'csharp'])
        .describe('Programming language'),
      vulnerabilityType: z.enum([
        'sql-injection',
        'xss',
        'command-injection',
        'path-traversal',
        'ssrf',
        'xxe',
        'deserialization',
        'authentication',
        'authorization',
        'cryptography',
        'hardcoded-secrets',
        'race-condition',
        'memory-safety',
        'other',
      ]).describe('Type of vulnerability'),
      cwe: z.string().optional().describe('CWE identifier if known (e.g., CWE-89)'),
      framework: z.string().optional().describe('Framework in use (e.g., Express, Django, Spring)'),
      constraints: z.string().optional().describe('Any constraints or requirements for the fix'),
    },
    ({ vulnerableCode, language, vulnerabilityType, cwe, framework, constraints }) => {
      const cweText = cwe ? `\n**CWE:** ${cwe}` : '';
      const frameworkText = framework ? `\n**Framework:** ${framework}` : '';
      const constraintsText = constraints ? `\n**Constraints:** ${constraints}` : '';

      const vulnerabilityGuidance: Record<string, string> = {
        'sql-injection': `
## SQL Injection Fix Guidelines
- Use parameterized queries/prepared statements
- Use ORM methods with proper escaping
- Never concatenate user input into SQL
- Validate and sanitize input as defense-in-depth
- Use least privilege database accounts`,
        'xss': `
## XSS Fix Guidelines
- Use context-aware output encoding
- Use framework's built-in escaping mechanisms
- Implement Content Security Policy (CSP)
- Sanitize HTML if rich text is required (use DOMPurify, bleach, etc.)
- Avoid innerHTML, use textContent instead`,
        'command-injection': `
## Command Injection Fix Guidelines
- Avoid shell execution when possible
- Use language-native APIs instead of shell commands
- If shell required, use array-based execution (no shell interpolation)
- Whitelist allowed commands/arguments
- Never pass user input directly to shell`,
        'path-traversal': `
## Path Traversal Fix Guidelines
- Canonicalize paths before validation
- Use allowlist of permitted directories
- Reject paths containing ../ or ..\\
- Use chroot or containerization for isolation
- Validate against base directory`,
        'ssrf': `
## SSRF Fix Guidelines
- Maintain allowlist of permitted hosts/IPs
- Block internal/private IP ranges
- Disable redirects or validate redirect targets
- Use network-level controls (firewall, egress filtering)
- Resolve DNS and validate IP before connection`,
        'xxe': `
## XXE Fix Guidelines
- Disable external entity processing
- Disable DTD processing entirely if not needed
- Use defused XML parsers
- Validate XML schema before parsing
- Use JSON instead of XML where possible`,
        'deserialization': `
## Deserialization Fix Guidelines
- Avoid deserializing untrusted data
- Use safe serialization formats (JSON instead of pickle/Java serialization)
- Implement integrity checks (HMAC) on serialized data
- Use allowlists for permitted classes
- Isolate deserialization in sandboxed environment`,
        'authentication': `
## Authentication Fix Guidelines
- Use established authentication libraries
- Implement proper password hashing (bcrypt, argon2)
- Use constant-time comparison for secrets
- Implement account lockout and rate limiting
- Use MFA where possible`,
        'authorization': `
## Authorization Fix Guidelines
- Check authorization on every request
- Use deny-by-default access control
- Validate object ownership before access
- Avoid direct object references (use indirect)
- Implement proper RBAC/ABAC`,
        'cryptography': `
## Cryptography Fix Guidelines
- Use modern algorithms (AES-256-GCM, ChaCha20-Poly1305)
- Use proper key derivation (PBKDF2, scrypt, argon2)
- Use cryptographically secure random number generators
- Avoid ECB mode, use GCM or CBC with HMAC
- Manage keys securely (HSM, KMS)`,
        'hardcoded-secrets': `
## Hardcoded Secrets Fix Guidelines
- Use environment variables or secret managers
- Use configuration files outside of version control
- Implement secret rotation capabilities
- Use vault solutions (HashiCorp Vault, AWS Secrets Manager)
- Never commit secrets to version control`,
        'race-condition': `
## Race Condition Fix Guidelines
- Use proper locking mechanisms (mutexes, semaphores)
- Use atomic operations where available
- Implement proper transaction isolation
- Use optimistic locking with version checking
- Avoid TOCTOU vulnerabilities with atomic check-and-use`,
        'memory-safety': `
## Memory Safety Fix Guidelines
- Use bounds checking for all array/buffer access
- Validate sizes before memory operations
- Use safe string functions (strlcpy, snprintf)
- Initialize all variables before use
- Free memory exactly once, null pointers after free`,
      };

      const guidance = vulnerabilityGuidance[vulnerabilityType] || '';

      return {
        messages: [
          {
            role: 'user' as const,
            content: {
              type: 'text' as const,
              text: `# Secure Code Fix Request

## Vulnerability Information
**Type:** ${vulnerabilityType.replace(/-/g, ' ').toUpperCase()}
**Language:** ${language}${cweText}${frameworkText}${constraintsText}

## Vulnerable Code

\`\`\`${language}
${vulnerableCode}
\`\`\`

---

Please provide a secure replacement for the vulnerable code above.

${guidance}

## Required Output

### 1. Vulnerability Analysis
- Explain exactly why the code is vulnerable
- Describe the potential attack vector
- Provide an example of how it could be exploited

### 2. Secure Code Implementation

Provide the fixed code with:
- Complete, working replacement code
- Inline comments explaining security measures
- Any required imports or dependencies

### 3. Code Comparison

Show a side-by-side or before/after comparison highlighting:
- What changed
- Why each change matters for security

### 4. Testing Recommendations

- How to verify the fix works correctly
- Security test cases to add
- Edge cases to consider

### 5. Additional Hardening (Optional)

- Defense-in-depth measures
- Related security improvements
- Logging/monitoring suggestions

## Format Requirements

- Provide production-ready code, not pseudocode
- Include error handling
- Follow ${language} best practices and idioms
- Use ${framework || 'standard library'} conventions where applicable
- Ensure backward compatibility unless explicitly breaking change is needed`,
            },
          },
        ],
      };
    }
  );
}
