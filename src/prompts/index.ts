import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerSecurityAuditPrompt } from './securityAudit.js';
import { registerThreatModelPrompt } from './threatModel.js';
import { registerVulnerabilityReportPrompt } from './vulnerabilityReport.js';
// Sprint 3: New prompts
import { registerIncidentResponsePrompt } from './incidentResponse.js';
import { registerSecureCodeFixPrompt } from './secureCodeFix.js';
import { registerComplianceAssessmentPrompt } from './complianceAssessment.js';

export function registerPrompts(server: McpServer): void {
  registerSecurityAuditPrompt(server);
  registerThreatModelPrompt(server);
  registerVulnerabilityReportPrompt(server);

  // Sprint 3: Incident response and remediation prompts
  registerIncidentResponsePrompt(server);
  registerSecureCodeFixPrompt(server);
  registerComplianceAssessmentPrompt(server);
}
