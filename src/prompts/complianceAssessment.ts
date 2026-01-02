import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerComplianceAssessmentPrompt(server: McpServer): void {
  server.prompt(
    'compliance-assessment',
    'Assess code against security compliance framework requirements',
    {
      code: z.string().describe('The code to assess for compliance'),
      framework: z.enum(['pci-dss', 'hipaa', 'soc2', 'gdpr', 'nist-csf', 'iso27001', 'owasp-asvs', 'cis'])
        .describe('Compliance framework to assess against'),
      language: z.enum(['javascript', 'typescript', 'python', 'go', 'java', 'c', 'cpp', 'rust', 'php', 'ruby', 'csharp'])
        .describe('Programming language'),
      applicationContext: z.string().optional().describe('Type of application (e.g., payment processing, healthcare, SaaS)'),
      dataTypes: z.array(z.enum([
        'pii',
        'phi',
        'financial',
        'credentials',
        'session',
        'audit-logs',
        'encryption-keys',
        'other',
      ])).optional().describe('Types of sensitive data handled'),
      scopeLevel: z.enum(['full', 'focused']).default('focused').describe('Assessment scope: full framework or focused on code-relevant controls'),
    },
    ({ code, framework, language, applicationContext, dataTypes, scopeLevel }) => {
      const contextText = applicationContext ? `\n**Application Context:** ${applicationContext}` : '';
      const dataTypesText = dataTypes?.length ? `\n**Sensitive Data Types:** ${dataTypes.join(', ')}` : '';

      const frameworkRequirements: Record<string, string> = {
        'pci-dss': `
## PCI-DSS v4.0 Code-Relevant Requirements

### Requirement 3: Protect Stored Account Data
- 3.4.1: PAN rendered unreadable using strong cryptography
- 3.5.1: Cryptographic keys protected against disclosure

### Requirement 4: Protect Cardholder Data During Transmission
- 4.2.1: Strong cryptography during transmission over open networks

### Requirement 6: Develop Secure Systems and Software
- 6.2.4: Secure coding practices addressing common vulnerabilities
- 6.3.1: Security vulnerabilities identified and managed
- 6.5.1-6.5.10: Protection against common vulnerabilities (injection, XSS, CSRF, etc.)

### Requirement 7: Restrict Access to System Components
- 7.2.2: Access based on least privilege principle

### Requirement 8: Identify Users and Authenticate Access
- 8.3.1: Strong authentication implemented
- 8.3.6: Password complexity requirements
- 8.6.1: Account lockout mechanisms`,

        'hipaa': `
## HIPAA Security Rule - Technical Safeguards

### 164.312(a)(1): Access Control
- Unique user identification
- Emergency access procedure
- Automatic logoff
- Encryption and decryption

### 164.312(b): Audit Controls
- Record and examine activity in systems containing ePHI

### 164.312(c)(1): Integrity
- Mechanisms to authenticate ePHI
- Protect ePHI from improper alteration

### 164.312(d): Authentication
- Verify person or entity seeking access

### 164.312(e)(1): Transmission Security
- Guard against unauthorized access to ePHI during transmission
- Encryption of ePHI in transit`,

        'soc2': `
## SOC 2 Trust Service Criteria (Code-Relevant)

### CC6: Logical and Physical Access Controls
- CC6.1: Logical access security software, infrastructure, and architectures
- CC6.6: Security of data in transit
- CC6.7: Security of data at rest

### CC7: System Operations
- CC7.1: Detection and monitoring of security events
- CC7.2: Vulnerability management

### CC8: Change Management
- CC8.1: Changes to infrastructure, data, and software

### PI1: Processing Integrity
- PI1.1: Complete, valid, accurate, timely, and authorized processing`,

        'gdpr': `
## GDPR Technical Measures (Article 32)

### Data Protection by Design (Article 25)
- Privacy by design and default
- Minimize data processing

### Security of Processing (Article 32)
- Pseudonymization and encryption
- Confidentiality, integrity, availability
- Ability to restore access to data
- Regular testing of security measures

### Data Subject Rights
- Right to access (Article 15)
- Right to erasure (Article 17)
- Data portability (Article 20)

### Breach Notification (Article 33-34)
- Logging and detection capabilities
- Ability to identify affected data subjects`,

        'nist-csf': `
## NIST Cybersecurity Framework 2.0 (Code-Relevant)

### Protect (PR)
- PR.AC: Identity Management and Access Control
- PR.DS: Data Security (encryption at rest and in transit)
- PR.IP: Information Protection Processes

### Detect (DE)
- DE.CM: Security Continuous Monitoring
- DE.AE: Anomalies and Events

### Respond (RS)
- RS.AN: Analysis capabilities for incidents
- RS.MI: Mitigation activities`,

        'iso27001': `
## ISO 27001:2022 Annex A Controls (Code-Relevant)

### A.8: Asset Management
- A.8.11: Data masking
- A.8.24: Use of cryptography

### A.9: Access Control
- A.9.2: User access provisioning
- A.9.4: Secure authentication

### A.14: Secure Development
- A.14.2.1: Secure development policy
- A.14.2.5: System security testing
- A.14.2.8: System security testing

### A.18: Compliance
- A.18.1.3: Protection of records`,

        'owasp-asvs': `
## OWASP Application Security Verification Standard 4.0

### V1: Architecture, Design and Threat Modeling
- V1.1: Secure development lifecycle requirements

### V2: Authentication
- V2.1: Password security requirements
- V2.5: Credential recovery requirements

### V3: Session Management
- V3.1: Fundamental session management security

### V4: Access Control
- V4.1: General access control design
- V4.2: Operation level access control

### V5: Validation, Sanitization and Encoding
- V5.1: Input validation
- V5.2: Sanitization and sandboxing
- V5.3: Output encoding

### V6: Stored Cryptography
- V6.2: Algorithms and key management

### V7: Error Handling and Logging
- V7.1: Log content requirements

### V8: Data Protection
- V8.1: General data protection`,

        'cis': `
## CIS Controls v8 (Code-Relevant)

### Control 3: Data Protection
- 3.6: Encrypt data on end-user devices
- 3.10: Encrypt sensitive data in transit
- 3.11: Encrypt sensitive data at rest

### Control 4: Secure Configuration
- 4.1: Establish secure configuration process
- 4.7: Manage default accounts

### Control 5: Account Management
- 5.2: Use unique passwords
- 5.4: Restrict administrator privileges

### Control 6: Access Control Management
- 6.1: Establish access granting process
- 6.8: Define and maintain role-based access control

### Control 8: Audit Log Management
- 8.2: Collect audit logs
- 8.5: Collect detailed audit logs`,
      };

      const requirements = frameworkRequirements[framework] || '';

      return {
        messages: [
          {
            role: 'user' as const,
            content: {
              type: 'text' as const,
              text: `# Compliance Assessment Request

## Assessment Parameters
**Framework:** ${framework.toUpperCase()}
**Language:** ${language}
**Scope:** ${scopeLevel === 'full' ? 'Full Framework Assessment' : 'Code-Relevant Controls Only'}${contextText}${dataTypesText}

## Code to Assess

\`\`\`${language}
${code}
\`\`\`

---

${requirements}

---

Please perform a compliance assessment of the code above against ${framework.toUpperCase()} requirements.

## Required Output

### 1. Executive Summary
- Overall compliance status (Compliant / Partially Compliant / Non-Compliant)
- Key findings summary
- Risk rating

### 2. Control-by-Control Assessment

For each relevant control, provide:

| Control ID | Control Name | Status | Finding | Evidence |
|------------|--------------|--------|---------|----------|
| Example    | Example Name | Pass/Fail/N/A | Description | Code reference |

### 3. Gap Analysis

For each gap identified:
- **Control:** The specific requirement not met
- **Current State:** What the code currently does
- **Required State:** What compliance requires
- **Risk Level:** Critical/High/Medium/Low
- **Remediation:** Specific steps to achieve compliance

### 4. Remediation Roadmap

Prioritized list of fixes:
1. Critical items (immediate action required)
2. High priority items (address within 30 days)
3. Medium priority items (address within 90 days)
4. Low priority items (address in next development cycle)

### 5. Evidence Collection Guidance

What documentation/artifacts to prepare for audit:
- Code documentation requirements
- Testing evidence needed
- Policy/procedure documentation
- Monitoring/logging evidence

### 6. Compliance Matrix

Summary table mapping code elements to framework requirements:

| Code Element | Framework Control | Status | Notes |
|--------------|-------------------|--------|-------|

## Additional Considerations

- Note any assumptions made during assessment
- Identify controls that require assessment beyond code review
- Suggest additional security measures beyond minimum compliance
- Note version-specific or framework-specific guidance`,
            },
          },
        ],
      };
    }
  );
}
