import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

export function registerIncidentResponsePrompt(server: McpServer): void {
  server.prompt(
    'incident-response',
    'Guide incident investigation and response for security events',
    {
      incidentType: z.enum([
        'data-breach',
        'malware',
        'unauthorized-access',
        'ddos',
        'insider-threat',
        'phishing',
        'ransomware',
        'supply-chain',
        'credential-compromise',
        'api-abuse',
        'unknown',
      ]).describe('Type of security incident'),
      description: z.string().describe('Detailed description of the incident'),
      affectedSystems: z.string().optional().describe('List of affected systems, services, or components'),
      indicators: z.string().optional().describe('Known indicators of compromise (IOCs): IPs, hashes, domains, etc.'),
      timeline: z.string().optional().describe('Known timeline of events'),
      severity: z.enum(['critical', 'high', 'medium', 'low']).default('high').describe('Initial severity assessment'),
    },
    ({ incidentType, description, affectedSystems, indicators, timeline, severity }) => {
      const affectedText = affectedSystems ? `\n\n**Affected Systems:** ${affectedSystems}` : '';
      const indicatorsText = indicators ? `\n\n**Known IOCs:** ${indicators}` : '';
      const timelineText = timeline ? `\n\n**Timeline:** ${timeline}` : '';

      const incidentTypeGuides: Record<string, string> = {
        'data-breach': `
### Data Breach Specific Actions
- Identify all affected data types (PII, financial, healthcare, etc.)
- Determine breach notification requirements (GDPR 72hrs, state laws, etc.)
- Preserve evidence for forensics and potential legal proceedings
- Check for data exfiltration indicators in network logs`,
        'malware': `
### Malware Specific Actions
- Isolate infected systems immediately
- Collect malware samples for analysis
- Check for lateral movement indicators
- Identify patient zero and infection vector
- Scan all endpoints with updated signatures`,
        'unauthorized-access': `
### Unauthorized Access Specific Actions
- Identify compromised credentials or access methods
- Review all access logs for the affected accounts
- Check for persistence mechanisms (new users, scheduled tasks)
- Audit privilege escalation attempts`,
        'ransomware': `
### Ransomware Specific Actions
- DO NOT pay ransom without consulting legal/insurance
- Isolate infected systems to prevent spread
- Identify ransomware variant and check for decryptors
- Assess backup integrity and recovery options
- Check for data exfiltration before encryption`,
        'ddos': `
### DDoS Specific Actions
- Engage DDoS mitigation service if available
- Identify attack vectors and traffic patterns
- Implement rate limiting and filtering
- Scale infrastructure if possible
- Coordinate with ISP/upstream providers`,
        'phishing': `
### Phishing Specific Actions
- Identify all recipients of the phishing campaign
- Check for credential harvesting or malware delivery
- Reset passwords for affected users
- Block sender domains and similar variations
- Review email gateway rules`,
        'credential-compromise': `
### Credential Compromise Specific Actions
- Force password reset for compromised accounts
- Review all activity from compromised credentials
- Check for unauthorized access to sensitive systems
- Audit MFA status and implementation
- Review for credential stuffing attacks`,
      };

      const specificGuide = incidentTypeGuides[incidentType] || '';

      return {
        messages: [
          {
            role: 'user' as const,
            content: {
              type: 'text' as const,
              text: `# Security Incident Response Guide

## Incident Details
**Type:** ${incidentType.replace(/-/g, ' ').toUpperCase()}
**Severity:** ${severity.toUpperCase()}
**Description:** ${description}${affectedText}${indicatorsText}${timelineText}

---

Please provide a comprehensive incident response plan following the NIST Incident Response Framework:

## 1. Identification & Triage

Analyze the incident and provide:
- Initial impact assessment
- Scope determination (users, systems, data affected)
- Attack vector hypothesis
- Initial classification and priority

## 2. Containment

### Immediate Actions (Short-term Containment)
- Steps to stop the bleeding
- Isolation procedures
- Evidence preservation requirements

### Extended Containment
- System hardening steps
- Network segmentation recommendations
- Access control modifications

## 3. Eradication

- Root cause analysis approach
- Malware/threat removal procedures
- Vulnerability remediation steps
- System cleaning/rebuilding guidance

## 4. Recovery

- Service restoration priority
- Verification and testing requirements
- Monitoring enhancements
- Gradual return to production

## 5. Lessons Learned

- Documentation requirements
- Process improvement recommendations
- Detection enhancement suggestions
- Training needs

${specificGuide}

## Required Output Format

For each phase, provide:
1. **Priority Actions**: Immediate steps ranked by importance
2. **Tools/Commands**: Specific commands or tools to use
3. **Evidence to Collect**: What to preserve for forensics
4. **Communication**: Who to notify and when
5. **Metrics**: How to measure success

Also include:
- Estimated timeline for each phase
- Resource requirements
- Potential blockers and mitigations
- Regulatory/compliance considerations`,
            },
          },
        ],
      };
    }
  );
}
