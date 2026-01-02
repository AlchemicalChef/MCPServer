import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerSecurityAuditPrompt(server: McpServer): void {
  server.prompt(
    'security-audit',
    'Perform a comprehensive security audit of code',
    {
      code: z.string().describe('The code to audit'),
      language: z.enum(['javascript', 'typescript', 'python', 'go', 'java', 'c', 'cpp', 'rust', 'php', 'ruby'])
        .describe('Programming language'),
      context: z.string().optional().describe('Additional context about the code (e.g., "authentication module", "API endpoint")'),
      focusAreas: z.array(z.enum([
        'injection',
        'authentication',
        'authorization',
        'cryptography',
        'data-exposure',
        'configuration',
        'error-handling',
        'all'
      ])).default(['all']).describe('Security areas to focus on'),
    },
    ({ code, language, context, focusAreas }) => {
      const focusText = focusAreas.includes('all')
        ? 'all security aspects'
        : focusAreas.join(', ');

      const contextText = context ? `\n\n**Context:** ${context}` : '';

      return {
        messages: [
          {
            role: 'user' as const,
            content: {
              type: 'text' as const,
              text: `Perform a comprehensive security audit of the following ${language} code, focusing on ${focusText}.${contextText}

## Audit Checklist

### 1. Injection Vulnerabilities
- SQL Injection
- Command Injection
- XSS (Cross-Site Scripting)
- LDAP Injection
- XML/XXE Injection
- NoSQL Injection

### 2. Authentication & Session
- Hardcoded credentials
- Weak password handling
- Session management issues
- JWT vulnerabilities

### 3. Authorization
- Missing access controls
- IDOR (Insecure Direct Object References)
- Privilege escalation

### 4. Cryptography
- Weak algorithms (MD5, SHA1)
- Insecure random number generation
- Key management issues
- Missing encryption

### 5. Data Exposure
- Sensitive data in logs
- Information leakage in errors
- Hardcoded secrets
- Insecure data storage

### 6. Security Misconfiguration
- Debug mode enabled
- Default credentials
- Unnecessary features enabled
- Missing security headers

### 7. Error Handling
- Stack traces exposed
- Verbose error messages
- Unhandled exceptions

## Required Output Format

For each vulnerability found, provide:
1. **Severity**: Critical/High/Medium/Low
2. **CWE ID**: The relevant CWE identifier
3. **Location**: Line number or code section
4. **Description**: What the vulnerability is
5. **Impact**: Potential consequences if exploited
6. **Remediation**: Specific fix with code example

## Code to Audit

\`\`\`${language}
${code}
\`\`\``,
            },
          },
        ],
      };
    }
  );
}
